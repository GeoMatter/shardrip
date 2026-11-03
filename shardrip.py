#!/usr/bin/env python3
"""
Shardrip - free multi-connection downloader and file sender, in one Python file.

DOWNLOAD
  Splits a file into chunks and downloads them in parallel over HTTP Range requests
  (optionally from several mirrors), resumes after interruptions, verifies SHA256.

SEND
  Shares a file from your PC over a Range-capable HTTP server. A free Cloudflare
  Quick Tunnel gives you a public https link (no port forwarding, works behind CGNAT).
  Shows a QR code for the link. Optional password Lock encrypts the file on the fly
  (AES-256-GCM), so only someone with the password can read it.

GUI
  A window with Download and Send tabs: python shardrip.py --gui
  (or double-click shardrip_gui.pyw)

Usage:
  Interactive:  python shardrip.py            (menu: download / send / window)
  Download:     python shardrip.py URL [MIRROR2 ...] -o file.iso -c 16 --sha256 <hash>
  Send:         python shardrip.py --serve "C:\\path\\file.iso" [--lock] [--no-tunnel]
  Window:       python shardrip.py --gui
  Browser:      python shardrip.py --web            (any browser, incl. phones via Termux)
  App window:   python shardrip.py --app            (the full app in its own window - what Shardrip.exe opens)
"""
import argparse
import getpass
import hashlib
import http.server
import ipaddress
import json
import math
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

VERSION = "2.6"
IS_WIN = platform.system() == "Windows"
IS_ANDROID = "ANDROID_ROOT" in os.environ or "TERMUX_VERSION" in os.environ or sys.platform == "android"
IS_APP = os.environ.get("SHARDRIP_APP") == "android"  # running inside Shardrip.apk
NO_WINDOW = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW: no console pop-ups from the GUI

# Packages that pip can't build on Android - Termux ships them ready-made instead.
TERMUX_PKGS = {"cryptography": "python-cryptography"}


def default_download_dir():
    forced = os.environ.get("SHARDRIP_DOWNLOAD_DIR")  # the Android app passes the phone's Download folder
    if forced and os.path.isdir(forced):
        return forced
    if IS_ANDROID:
        phone = os.path.expanduser("~/storage/downloads")  # created by `termux-setup-storage`
        if os.path.isdir(phone):
            return phone
    return os.path.join(os.path.expanduser("~"), "Downloads")


def ensure_package(pip_name, import_name=None):
    """Import a package, installing it with pip on first use if it's missing."""
    import importlib
    try:
        return importlib.import_module(import_name or pip_name)
    except ImportError:
        if getattr(sys, "frozen", False):
            raise RuntimeError(f"'{pip_name}' wasn't included when this Shardrip.exe was built")
        if IS_APP:
            raise RuntimeError(f"'{pip_name}' wasn't included when this Shardrip app was built")
        if IS_ANDROID and pip_name in TERMUX_PKGS:
            raise RuntimeError(f"'{pip_name}' is missing. In Termux run:  pkg install {TERMUX_PKGS[pip_name]}")
        print(f"Installing '{pip_name}' (one-time)...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name],
                              creationflags=NO_WINDOW)
        importlib.invalidate_caches()
        return importlib.import_module(import_name or pip_name)


requests = ensure_package("requests")

READ_SIZE = 256 * 1024
UA = {"User-Agent": f"shardrip/{VERSION}"}
_local = threading.local()

CLOUDFLARED_BASE = "https://github.com/cloudflare/cloudflared/releases/latest/download/"
CLOUDFLARED_ASSETS = {
    ("Windows", "amd64"): "cloudflared-windows-amd64.exe",
    ("Windows", "x86_64"): "cloudflared-windows-amd64.exe",
    ("Windows", "arm64"): "cloudflared-windows-amd64.exe",  # runs under emulation
    ("Linux", "x86_64"): "cloudflared-linux-amd64",
    ("Linux", "amd64"): "cloudflared-linux-amd64",
    ("Linux", "aarch64"): "cloudflared-linux-arm64",
    ("Linux", "arm64"): "cloudflared-linux-arm64",
}


class Stopped(Exception):
    """Raised when the user stops a download/share."""


# ============================================================================
# Small helpers
# ============================================================================

def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def fmt_eta(seconds):
    seconds = int(max(seconds, 0))
    if seconds >= 3600:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 60}m{seconds % 60:02d}s"


def session():
    """One requests.Session per thread (keeps connections alive)."""
    if not hasattr(_local, "s"):
        _local.s = requests.Session()
        _local.s.headers.update(UA)
    return _local.s


def probe(url):
    """Return (size, supports_ranges) using a 1-byte Range request."""
    r = requests.get(url, headers={**UA, "Range": "bytes=0-0"},
                     stream=True, allow_redirects=True, timeout=20)
    try:
        if r.status_code == 206 and "Content-Range" in r.headers:
            return int(r.headers["Content-Range"].split("/")[-1]), True
        r.raise_for_status()
        return int(r.headers.get("Content-Length", 0)), False
    finally:
        r.close()


def fetch_bytes(url, start, end):
    """Fetch an exact byte range (used for resume identity checks)."""
    with session().get(url, headers={"Range": f"bytes={start}-{end}"}, timeout=20) as r:
        if r.status_code != 206:
            raise IOError(f"HTTP {r.status_code}")
        return r.content


def sha256_file(path, on_progress=None, stop=None):
    h = hashlib.sha256()
    total = os.path.getsize(path) or 1
    done = 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            if stop is not None and stop.is_set():
                raise Stopped()
            h.update(block)
            done += len(block)
            if on_progress:
                on_progress(done, total)
    return h.hexdigest()


def url_filename(url):
    return urllib.parse.unquote(os.path.basename(url.split("?")[0])) or "download.bin"


# ----------------------------------------------------------------------------
# Smart links: ONE link that downloads over the local network (Wi-Fi/LAN) when
# the sender is on the same network, and over the internet (Cloudflare) when not:
#     https://xxx.trycloudflare.com/TOKEN/file?lan=10.217.17.126:8080,192.168.1.5:8080
# The ?lan= part is ignored by the sender's server, by browsers and by older
# Shardrip versions, so a smart link always still works as a normal link.
# ----------------------------------------------------------------------------
VIA = {"auto": "Auto", "lan": "Same network only", "internet": "Internet only"}
_TAILSCALE_NET = ipaddress.IPv4Network("100.64.0.0/10")


def _local_ip_ok(host, tailscale=True):
    """Only private (or Tailscale) IPv4 addresses count as local-network addresses."""
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return False
    return ip.is_private or (tailscale and ip in _TAILSCALE_NET)


def make_smart_link(base, hosts):
    """Add local-network addresses ("ip:port") to a link. Leaves it plain if there are none."""
    own = urllib.parse.urlsplit(base).netloc
    hosts = [h for h in dict.fromkeys(hosts) if h != own]
    return f"{base}?lan={','.join(hosts)}" if hosts else base


def split_smart_link(url):
    """-> (the link without the hint, [local-network URLs of the same file, best first])."""
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    hints = ",".join(v for k, v in query if k == "lan")
    rest = urllib.parse.urlencode([(k, v) for k, v in query if k != "lan"])
    base = urllib.parse.urlunsplit(parts._replace(query=rest))
    local = []
    for h in hints.split(","):
        host, _, port = h.strip().rpartition(":")
        if host and port.isdigit() and 0 < int(port) < 65536 and _local_ip_ok(host):
            u = urllib.parse.urlunsplit(("http", f"{host}:{int(port)}", parts.path, rest, ""))
            if u not in local:
                local.append(u)
    return base, local[:6]


def is_local_url(url):
    return _local_ip_ok(urllib.parse.urlsplit(url).hostname or "")


def first_reachable(urls, timeout=2.5):
    """Quickly check several links at once; return the first (in order) that serves the file."""
    if not urls:
        return None

    def ok(u):
        try:
            r = requests.get(u, headers={**UA, "Range": "bytes=0-0"}, stream=True,
                             timeout=(timeout, timeout), allow_redirects=False)
            r.close()
            return r.status_code == 206
        except requests.RequestException:
            return False

    with ThreadPoolExecutor(max_workers=len(urls)) as ex:
        results = list(ex.map(ok, urls))
    return next((u for u, good in zip(urls, results) if good), None)


class Links:
    """Which link each chunk downloads from.

    Uses the local-network link while it works; if it stops answering (you left the
    Wi-Fi) it switches to the internet link, and switches back when the local link
    answers again (checked every RECHECK seconds in the background)."""
    RECHECK = 30

    def __init__(self, remote, local_candidates=(), local=None, extras=(), ui=None):
        self.remote = list(remote)              # internet link (+ mirrors); empty = "same network only"
        self.candidates = list(local_candidates)
        self.local = local                      # local-network link in use, or None
        self.extras = list(extras)
        self.ui = ui
        self.lock = threading.Lock()
        self.next_check = time.time() + self.RECHECK
        self.checking = False

    def active(self):
        return ([self.local] + self.extras) if self.local else self.remote

    def pick(self, idx, attempt):
        with self.lock:
            if (not self.local and self.candidates and self.remote and not self.checking
                    and time.time() >= self.next_check):
                self.checking = True
                threading.Thread(target=self._recheck, daemon=True).start()
            urls = self.active()
            return urls[(idx + attempt) % len(urls)]

    def failed(self, url):
        with self.lock:
            if url == self.local and self.remote:
                self.local = None
                self.next_check = time.time() + self.RECHECK
                if self.ui:
                    self.ui.log("🌐 Lost the local network connection - switched to the internet link.")

    def _recheck(self):
        found = first_reachable(self.candidates)
        with self.lock:
            self.checking = False
            self.next_check = time.time() + self.RECHECK
            if found and not self.local:
                self.local = found
                if self.ui:
                    self.ui.log("📶 The sender is reachable on your network again - switched to the local link.")


def gen_password():
    """Readable random password, e.g. 'kp7x-9qmr-w3hd-t8ne' (~79 bits)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))


class Progress:
    """Thread-safe byte counter shared by worker threads and whoever displays progress."""

    def __init__(self, total, already=0, label=""):
        self.total, self.done, self.label = total, already, label
        self.start_done, self.t0 = already, time.time()
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self.after_finish = None

    def add(self, n):
        with self.lock:
            self.done += n

    def snapshot(self):
        with self.lock:
            done = self.done
        el = max(time.time() - self.t0, 1e-6)
        speed = (done - self.start_done) / el
        eta = (self.total - done) / speed if speed > 0 else 0
        pct = done / self.total * 100 if self.total else 0
        return done, self.total, speed, eta, pct

    def finish(self):
        if not self.finished.is_set():
            self.finished.set()
            if self.after_finish:
                self.after_finish()


# ============================================================================
# QR code generator (byte mode, versions 1-40) - no extra packages needed
# Based on the ISO/IEC 18004 algorithm (structure follows Project Nayuki's design).
# ============================================================================

_ECC_CODEWORDS_PER_BLOCK = (
    # L
    (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30,
     26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    # M
    (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28,
     28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
)
_NUM_ECC_BLOCKS = (
    # L
    (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15,
     16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    # M
    (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26,
     28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
)
_ECL_FORMAT_BITS = (1, 0)  # L, M


def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _raw_data_modules(ver):
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        numalign = ver // 7 + 2
        result -= (25 * numalign - 10) * numalign - 55
        if ver >= 7:
            result -= 36
    return result


def _num_data_codewords(ver, ecl):
    return _raw_data_modules(ver) // 8 - _ECC_CODEWORDS_PER_BLOCK[ecl][ver] * _NUM_ECC_BLOCKS[ecl][ver]


def _alignment_positions(ver, size):
    if ver == 1:
        return []
    numalign = ver // 7 + 2
    step = (ver * 8 + numalign * 3 + 5) // (numalign * 4 - 4) * 2
    result = [size - 7 - i * step for i in range(numalign - 1)] + [6]
    return list(reversed(result))


def qr_encode(text, ecl=1, force_mask=None):
    """Encode text as a QR code. ecl: 0 = L, 1 = M. Returns a square list of lists of bools."""
    data = text.encode("utf-8")
    for ver in range(1, 41):
        cc_bits = 8 if ver <= 9 else 16
        if 4 + cc_bits + 8 * len(data) <= _num_data_codewords(ver, ecl) * 8:
            break
    else:
        raise ValueError("Text too long for a QR code")

    # --- data bits ---
    bits = []

    def put(val, n):
        bits.extend((val >> i) & 1 for i in reversed(range(n)))

    put(0b0100, 4)
    put(len(data), cc_bits)
    for b in data:
        put(b, 8)
    cap = _num_data_codewords(ver, ecl) * 8
    put(0, min(4, cap - len(bits)))
    put(0, (-len(bits)) % 8)
    pad = 0xEC
    while len(bits) < cap:
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]

    # --- error correction + interleaving ---
    numblocks = _NUM_ECC_BLOCKS[ecl][ver]
    blockecclen = _ECC_CODEWORDS_PER_BLOCK[ecl][ver]
    rawcodewords = _raw_data_modules(ver) // 8
    numshortblocks = numblocks - rawcodewords % numblocks
    shortblocklen = rawcodewords // numblocks
    rsdiv = _rs_divisor(blockecclen)
    blocks, k = [], 0
    for i in range(numblocks):
        dat = codewords[k:k + shortblocklen - blockecclen + (0 if i < numshortblocks else 1)]
        k += len(dat)
        ecc = _rs_remainder(dat, rsdiv)
        if i < numshortblocks:
            dat = dat + [0]
        blocks.append(dat + ecc)
    allcw = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != shortblocklen - blockecclen or j >= numshortblocks:
                allcw.append(blk[i])

    # --- function patterns ---
    size = ver * 4 + 17
    mods = [[False] * size for _ in range(size)]
    func = [[False] * size for _ in range(size)]

    def setf(x, y, dark):
        mods[y][x] = dark
        func[y][x] = True

    for i in range(size):
        setf(6, i, i % 2 == 0)
        setf(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    setf(x, y, max(abs(dx), abs(dy)) not in (2, 4))
    pos = _alignment_positions(ver, size)
    n = len(pos)
    for i in range(n):
        for j in range(n):
            if (i == 0 and j == 0) or (i == 0 and j == n - 1) or (i == n - 1 and j == 0):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    setf(pos[i] + dx, pos[j] + dy, max(abs(dx), abs(dy)) != 1)

    def draw_format(mask):
        d = _ECL_FORMAT_BITS[ecl] << 3 | mask
        rem = d
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        fbits = (d << 10 | rem) ^ 0x5412
        bit = lambda i: ((fbits >> i) & 1) != 0
        for i in range(6):
            setf(8, i, bit(i))
        setf(8, 7, bit(6))
        setf(8, 8, bit(7))
        setf(7, 8, bit(8))
        for i in range(9, 15):
            setf(14 - i, 8, bit(i))
        for i in range(8):
            setf(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            setf(8, size - 15 + i, bit(i))
        setf(8, size - 8, True)

    draw_format(0)  # reserve format areas
    if ver >= 7:
        rem = ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        vbits = ver << 12 | rem
        for i in range(18):
            b = ((vbits >> i) & 1) != 0
            a, c = size - 11 + i % 3, i // 3
            setf(a, c, b)
            setf(c, a, b)

    # --- place codewords (zig-zag) ---
    i = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = (size - 1 - vert) if upward else vert
                if not func[y][x] and i < len(allcw) * 8:
                    mods[y][x] = ((allcw[i >> 3] >> (7 - (i & 7))) & 1) != 0
                    i += 1
        right -= 2

    masks = (
        lambda x, y: (x + y) % 2 == 0,
        lambda x, y: y % 2 == 0,
        lambda x, y: x % 3 == 0,
        lambda x, y: (x + y) % 3 == 0,
        lambda x, y: (x // 3 + y // 2) % 2 == 0,
        lambda x, y: x * y % 2 + x * y % 3 == 0,
        lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
        lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
    )

    def apply_mask(m):
        f = masks[m]
        for y in range(size):
            for x in range(size):
                if not func[y][x] and f(x, y):
                    mods[y][x] = not mods[y][x]

    def penalty():
        score = 0
        rows = mods
        cols = [list(c) for c in zip(*mods)]
        for lines in (rows, cols):
            for line in lines:
                run = 1
                for k in range(1, size):
                    if line[k] == line[k - 1]:
                        run += 1
                    else:
                        if run >= 5:
                            score += run - 2
                        run = 1
                if run >= 5:
                    score += run - 2
                ints = [1 if v else 0 for v in line]
                for k in range(size - 10):
                    seg = ints[k:k + 11]
                    if seg == [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0] or seg == [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]:
                        score += 40
        for y in range(size - 1):
            for x in range(size - 1):
                c = mods[y][x]
                if c == mods[y][x + 1] == mods[y + 1][x] == mods[y + 1][x + 1]:
                    score += 3
        dark = sum(sum(1 for v in row if v) for row in mods)
        total = size * size
        score += 10 * (abs(dark * 20 - total * 10) // total)
        return score

    best, best_score = 0, None
    for m in (range(8) if force_mask is None else [force_mask]):
        apply_mask(m)
        draw_format(m)
        s = penalty()
        if best_score is None or s < best_score:
            best, best_score = m, s
        apply_mask(m)  # undo (XOR)
    apply_mask(best)
    draw_format(best)
    return mods


def qr_terminal(matrix, quiet=2):
    """Render a QR matrix with half-block characters (2 rows per text line).
    Light modules are drawn as filled blocks, so it scans on dark-background terminals."""
    n = len(matrix)
    size = n + quiet * 2

    def light(x, y):
        x -= quiet
        y -= quiet
        if 0 <= x < n and 0 <= y < n:
            return not matrix[y][x]
        return True

    lines = []
    for y in range(0, size, 2):
        row = []
        for x in range(size):
            top = light(x, y)
            bot = light(x, y + 1) if y + 1 < size else False
            row.append("█" if top and bot else "▀" if top else "▄" if bot else " ")
        lines.append("".join(row))
    return "\n".join(lines)


# ============================================================================
# Lock: password encryption (AES-256-GCM, per-1MiB block, random-access)
#
# Locked stream layout:
#   header = MAGIC(8) | salt(16) | block_size(4) | plain_size(8) | check(16)
#   then for each 1 MiB plaintext block i: AESGCM(key).encrypt(nonce_i, block, aad=header)
# key = scrypt(password, salt). A new random salt per share = a new key per share,
# so nonce_i (= block index) is never reused under the same key.
# ============================================================================

LOCK_MAGIC = b"SHRDLCK1"
LOCK_BLOCK = 1024 * 1024
LOCK_HDR_BASE = 36
LOCK_HDR = LOCK_HDR_BASE + 16
CHECK_NONCE = b"\xff" * 12
LOCK_EXT = ".shardlock"


class WrongPassword(Exception):
    pass


def _aesgcm():
    ensure_package("cryptography")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM


def _derive_key(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def _block_nonce(i):
    return b"\x00\x00\x00\x00" + struct.pack(">Q", i)


def is_locked_file(path):
    try:
        with open(path, "rb") as f:
            return f.read(len(LOCK_MAGIC)) == LOCK_MAGIC
    except OSError:
        return False


class FileSource:
    """Serves a file as-is."""

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)

    def iter_range(self, start, end):
        with open(self.path, "rb") as f:
            f.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                data = f.read(min(READ_SIZE, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data


class EncryptedSource:
    """Serves an encrypted view of a file, encrypting only the blocks each request needs."""

    def __init__(self, path, password):
        AESGCM = _aesgcm()
        self.path = path
        self.plain_size = os.path.getsize(path)
        salt = os.urandom(16)
        key = _derive_key(password, salt)
        base = LOCK_MAGIC + salt + struct.pack(">IQ", LOCK_BLOCK, self.plain_size)
        self._aes = AESGCM(key)
        self.header = base + self._aes.encrypt(CHECK_NONCE, b"", base)
        self.nblocks = math.ceil(self.plain_size / LOCK_BLOCK)
        self.size = LOCK_HDR + self.plain_size + 16 * self.nblocks
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def _block(self, i):
        with self._lock:
            if i in self._cache:
                self._cache.move_to_end(i)
                return self._cache[i]
        with open(self.path, "rb") as f:
            f.seek(i * LOCK_BLOCK)
            pt = f.read(min(LOCK_BLOCK, self.plain_size - i * LOCK_BLOCK))
        ct = self._aes.encrypt(_block_nonce(i), pt, self.header)
        with self._lock:
            self._cache[i] = ct
            while len(self._cache) > 48:
                self._cache.popitem(last=False)
        return ct

    def iter_range(self, start, end):
        stride = LOCK_BLOCK + 16
        pos = start
        while pos <= end:
            if pos < LOCK_HDR:
                piece = self.header[pos:min(LOCK_HDR, end + 1)]
            else:
                i = (pos - LOCK_HDR) // stride
                if i >= self.nblocks:
                    break
                off = pos - (LOCK_HDR + i * stride)
                piece = self._block(i)[off:off + (end - pos + 1)]
            if not piece:
                break
            yield piece
            pos += len(piece)


def decrypt_file(enc_path, out_path, password, ui, stop=None):
    """Decrypt a .shardlock file. Raises WrongPassword or ValueError (corrupted)."""
    AESGCM = _aesgcm()
    from cryptography.exceptions import InvalidTag
    with open(enc_path, "rb") as f:
        base = f.read(LOCK_HDR_BASE)
        if len(base) < LOCK_HDR_BASE or base[:8] != LOCK_MAGIC:
            raise ValueError("Not a Shardrip locked file")
        salt = base[8:24]
        block, plain_size = struct.unpack(">IQ", base[24:36])
        check = f.read(16)
        header = base + check
        aes = AESGCM(_derive_key(password, salt))
        try:
            aes.decrypt(CHECK_NONCE, check, base)
        except InvalidTag:
            raise WrongPassword()
        nblocks = math.ceil(plain_size / block)
        if os.path.getsize(enc_path) != LOCK_HDR + plain_size + 16 * nblocks:
            raise ValueError("Locked file is incomplete or corrupted")

        prog = ui.start_progress(plain_size, 0, "Decrypting")
        tmp = out_path + ".part"
        try:
            with open(tmp, "wb") as o:
                for i in range(nblocks):
                    if stop is not None and stop.is_set():
                        raise Stopped()
                    ct = f.read(min(block, plain_size - i * block) + 16)
                    try:
                        pt = aes.decrypt(_block_nonce(i), ct, header)
                    except InvalidTag:
                        raise ValueError(f"Block {i} failed verification - the file is corrupted or was tampered with")
                    o.write(pt)
                    prog.add(len(pt))
        except BaseException:
            prog.finish()
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        prog.finish()
    os.replace(tmp, out_path)


# ============================================================================
# Download engine
# ============================================================================

def fetch_chunk(links, idx, start, end, path, prog, stop, retries=6):
    """Download bytes [start, end] into path at offset start. Rotates mirrors / switches link on failure."""
    if not isinstance(links, Links):
        links = Links(links)
    for attempt in range(retries):
        if stop.is_set():
            raise Stopped()
        url = links.pick(idx, attempt)
        got = 0
        try:
            with session().get(url, headers={"Range": f"bytes={start}-{end}"},
                               stream=True, timeout=(10, 30)) as r:
                if r.status_code != 206:
                    raise IOError(f"HTTP {r.status_code} (link expired or no range support?)")
                buf = bytearray()
                for block in r.iter_content(READ_SIZE):
                    if stop.is_set():
                        raise Stopped()
                    buf += block
                    got += len(block)
                    prog.add(len(block))
            if len(buf) != end - start + 1:
                raise IOError(f"short read {len(buf)} != {end - start + 1}")
            with open(path, "r+b") as f:
                f.seek(start)
                f.write(buf)
            return idx
        except Stopped:
            prog.add(-got)
            raise
        except Exception as e:
            prog.add(-got)  # roll back progress for the failed attempt
            links.failed(url)
            if attempt == retries - 1:
                raise RuntimeError(f"chunk {idx} failed: {e}")
            if stop.wait(min(2 ** attempt, 15)):
                raise Stopped()


def single_stream(url, path, size, ui, stop):
    ui.log("Server doesn't support ranges -> single connection download.")
    prog = ui.start_progress(size, 0)
    try:
        with session().get(url, stream=True, timeout=30) as r, open(path, "wb") as f:
            r.raise_for_status()
            for block in r.iter_content(READ_SIZE):
                if stop.is_set():
                    raise Stopped()
                f.write(block)
                prog.add(len(block))
    finally:
        prog.finish()


def choose_links(urls, via, ui):
    """Smart links: use the local network if the sender is on it, else the internet link."""
    via = via if via in VIA else "auto"
    base, local_urls = split_smart_link(urls[0])
    extras = urls[1:]
    if via == "internet":
        local_urls = []
    if via == "lan" and not local_urls:
        if not is_local_url(base):
            raise ValueError("This link has no same-network address (it's internet-only, or made by an older "
                             "Shardrip). Choose Auto or Internet only.")
        local_urls = [base]
    local = None
    if local_urls:
        ui.log("Looking for the sender on your network...")
        local = first_reachable(local_urls)
        if local:
            ui.log("📶 The sender is on your network - downloading directly over Wi-Fi/LAN (fastest).")
        elif via == "lan":
            raise IOError("Couldn't reach the sender on this network. Are you on the same Wi-Fi? "
                          "(Or choose Auto / Internet only.)")
        else:
            ui.log("🌐 The sender isn't on your network - downloading over the internet link.")
    remote = [] if via == "lan" else [base] + extras
    return Links(remote, local_urls if via == "auto" else [], local, extras, ui)


def download(urls, out, ui, connections=16, chunk_mb=16, sha256=None, password=None,
             overwrite=False, stop=None, via="auto"):
    """Download urls -> out. Returns the final file path, or None if cancelled/failed.
    via: "auto" (local network if the sender is on it, else internet), "lan" or "internet"."""
    stop = stop or threading.Event()
    out = os.path.abspath(out)
    state_path = out + ".state"
    os.makedirs(os.path.dirname(out), exist_ok=True)

    links = choose_links(urls, via, ui)
    first = links.active()[0]
    size, ranges = probe(first)

    def same_file(u):
        try:
            s, r = probe(u)
            if s == size and r:
                return True
            ui.log(f"Skipping mirror (size/range mismatch): {u}")
        except Exception as e:
            ui.log(f"Skipping mirror ({e}): {u}")
        return False

    links.extras = [u for u in links.extras if same_file(u)]
    if links.local:
        # The internet link is only the backup: keep it if it serves the same file, quietly drop it if not.
        base = links.remote[0] if links.remote else None
        try:
            ok = base is not None and probe(base) == (size, True)
        except Exception:
            ok = False
        links.remote = ([base] if ok else []) + links.extras
    else:
        links.remote = [first] + links.extras
    urls = links.active()
    ui.log(f"File: {out}\nSize: {human(size)}  Mirrors: {len(urls)}  Connections: {connections}")

    # Never silently wipe a file that's already there (e.g. a finished download).
    # A .state file next to it means it's a resumable partial download, which is fine.
    if os.path.exists(out) and not os.path.exists(state_path) and not overwrite:
        if is_locked_file(out) and os.path.getsize(out) == size:
            ui.log("Already downloaded (still locked) - skipping straight to unlocking.")
            return _after_download(out, ui, sha256, password, stop)
        ui.log(f"⚠️  {os.path.basename(out)} already exists ({human(os.path.getsize(out))}).")
        if sha256:
            ui.log("Checking whether it's already complete...")
            if sha256_file(out, stop=stop).lower() == sha256.lower():
                ui.log("It's already fully downloaded and the SHA256 matches ✅ - nothing to do.")
                return out
            ui.log("Its SHA256 doesn't match, so it's incomplete or a different file.")
        if not ui.confirm(f"{os.path.basename(out)} already exists. Overwrite it?"):
            ui.log("Cancelled - existing file left untouched.")
            return None

    if not ranges or size == 0:
        single_stream(urls[0], out, size, ui, stop)
    else:
        chunk = chunk_mb * 1024 * 1024
        chunks = [(i, s, min(s + chunk, size) - 1) for i, s in enumerate(range(0, size, chunk))]

        done = set()
        if os.path.exists(state_path) and os.path.exists(out):
            try:
                with open(state_path) as f:
                    st = json.load(f)
                if st.get("size") == size and st.get("chunk") == chunk:
                    done = set(st["done"])
            except (ValueError, KeyError):
                ui.log("State file unreadable, starting fresh.")
            # Make sure the server still has the SAME file (e.g. a re-shared locked file
            # gets a new key, so old chunks would no longer fit together).
            if 0 in done:
                n = min(64, size)
                try:
                    with open(out, "rb") as f:
                        local = f.read(n)
                    if fetch_bytes(urls[0], 0, n - 1) != local:
                        ui.log("The file on the server has changed since last time - starting fresh.")
                        done = set()
                except Exception:
                    pass
            if done:
                ui.log(f"Resuming: {len(done)}/{len(chunks)} chunks already done")
        if not done:
            with open(out, "wb") as f:
                f.truncate(size)  # pre-allocate

        already = sum(e - s + 1 for i, s, e in chunks if i in done)
        prog = ui.start_progress(size, already)
        todo = [c for c in chunks if c[0] not in done]
        failed = []
        pool = ThreadPoolExecutor(max_workers=connections)
        pending = {pool.submit(fetch_chunk, links, i, s, e, out, prog, stop) for i, s, e in todo}
        try:
            # Poll with a short timeout so Ctrl+C / Stop is noticed quickly
            while pending and not stop.is_set():
                finished, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for fut in finished:
                    try:
                        idx = fut.result()
                        done.add(idx)
                        tmp = state_path + ".tmp"
                        with open(tmp, "w") as f:
                            json.dump({"size": size, "chunk": chunk, "done": sorted(done)}, f)
                        os.replace(tmp, state_path)  # atomic: never a half-written state file
                    except Stopped:
                        pass
                    except Exception as e:
                        failed.append(str(e))
        except KeyboardInterrupt:
            stop.set()
            prog.finish()
            ui.log(f"Stopped at {len(done)}/{len(chunks)} chunks. Run it again to resume.")
            raise
        if stop.is_set():
            for f in pending:
                f.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            prog.finish()
            ui.log(f"Stopped at {len(done)}/{len(chunks)} chunks. Run it again to resume.")
            return None
        pool.shutdown()
        prog.finish()
        if failed:
            ui.log(f"{len(failed)} chunk(s) failed ({failed[0]}). Run it again to retry them.")
            return None
        os.remove(state_path)

    ui.log(f"Downloaded: {out}")
    return _after_download(out, ui, sha256, password, stop)


def _after_download(out, ui, sha256, password, stop):
    """Unlock (if locked) and verify. Returns the final path or None."""
    final = out
    if is_locked_file(out):
        final = finish_locked(out, ui, password, stop)
        if not final:
            return None

    if sha256:
        ui.log("Verifying SHA256...")
        got = sha256_file(final, stop=stop)
        if got.lower() != sha256.lower():
            ui.log(f"SHA256 MISMATCH ❌\n expected {sha256}\n got      {got}")
            return None
        ui.log("SHA256 OK ✅")
    ui.log(f"Done: {final}")
    return final


def finish_locked(enc_path, ui, password, stop):
    """Decrypt a downloaded .shardlock file. Returns the decrypted path or None."""
    dest = enc_path[:-len(LOCK_EXT)] if enc_path.endswith(LOCK_EXT) else enc_path + ".unlocked"
    ui.log("🔒 This file is password-locked.")
    if os.path.exists(dest) and not ui.confirm(f"{os.path.basename(dest)} already exists. Overwrite it?"):
        ui.log(f"Kept the locked file: {enc_path}")
        return None
    for attempt in range(3):
        pw = password if (attempt == 0 and password) else ui.ask_password()
        if not pw:
            break
        try:
            ui.log("Decrypting...")
            decrypt_file(enc_path, dest, pw, ui, stop)
            os.remove(enc_path)
            ui.log("Unlocked ✅ (every block verified - nothing was tampered with)")
            return dest
        except WrongPassword:
            ui.log("Wrong password.")
        except ValueError as e:
            ui.log(f"❌ {e}")
            return None
    ui.log(f"Still locked. Your download is safe - run it again with the right password:\n  {enc_path}")
    return None


# ============================================================================
# Send engine
# ============================================================================

def lan_ip():
    """Best-guess LAN IP (no packets are actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def lan_ips():
    """Every local-network IPv4 address this device has, best guess first.
    (PCs often have several adapters - Wi-Fi, Ethernet, VPNs - so one guess can be the wrong one.)"""
    best = lan_ip()
    found = [best]
    try:
        found += [a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    except OSError:
        pass
    ips = [ip for ip in dict.fromkeys(found) if _local_ip_ok(ip, tailscale=False)]
    return ips[:4] or [best]


def tailscale_ip():
    """Tailscale IPv4 if Tailscale is installed and connected, else None."""
    exe = shutil.which("tailscale")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "ip", "-4"], capture_output=True, text=True, timeout=5,
                             creationflags=NO_WINDOW)
        lines = out.stdout.strip().splitlines()
        return lines[0] if out.returncode == 0 and lines else None
    except (OSError, subprocess.SubprocessError):
        return None


def find_cloudflared(ui):
    """Find cloudflared on PATH or next to this script; download it from GitHub if missing."""
    # In a packaged Shardrip.exe, keep cloudflared next to the .exe (not in a temp folder)
    here = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
    local = os.path.join(here, "cloudflared.exe" if IS_WIN else "cloudflared")
    found = shutil.which("cloudflared") or (local if os.path.isfile(local) else None)
    if found:
        return found
    if IS_ANDROID:
        ui.log("cloudflared isn't installed. In Termux run:  pkg install cloudflared")
        return None

    asset =CLOUDFLARED_ASSETS.get((platform.system(), platform.machine().lower()))
    if not asset:
        ui.log("No automatic cloudflared download for this OS - install it from "
               "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
        return None

    ui.log("Downloading cloudflared (one-time, ~40 MB, official Cloudflare release from GitHub)...")
    try:
        with requests.get(CLOUDFLARED_BASE + asset, stream=True, timeout=60, headers=UA) as r:
            r.raise_for_status()
            tmp = local + ".part"
            with open(tmp, "wb") as f:
                for block in r.iter_content(READ_SIZE):
                    f.write(block)
        os.replace(tmp, local)
        if not IS_WIN:
            os.chmod(local, 0o755)
        return local
    except Exception as e:
        ui.log(f"Couldn't download cloudflared: {e}")
        return None


def start_tunnel(port, ui, timeout=60):
    """Start a Cloudflare Quick Tunnel to localhost:port. Returns (process, public_url) or (None, None)."""
    exe = find_cloudflared(ui)
    if not exe:
        return None, None
    proc = subprocess.Popen(
        [exe, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        text=True, bufsize=1, encoding="utf-8", errors="replace", creationflags=NO_WINDOW,
    )
    found = queue.Queue()
    last_error = []

    def drain():
        # Keep reading forever: if the pipe fills up, cloudflared would stall.
        sent = False
        for line in proc.stdout:
            if not sent:
                m = TUNNEL_URL_RE.search(line)
                if m:
                    found.put(m.group(0))
                    sent = True
                elif " ERR " in line or "failed" in line.lower():
                    last_error[:] = [line.strip()]
        if not sent:
            found.put(None)

    threading.Thread(target=drain, daemon=True).start()
    try:
        url = found.get(timeout=timeout)
    except queue.Empty:
        url = None
    if not url:
        proc.terminate()
        if last_error:
            ui.log(f"Cloudflare said: {_tunnel_error_hint(last_error[0])}")
        return None, None
    return proc, url


# A real Quick Tunnel address is random words joined by hyphens, e.g.
# https://silicon-nut-your-talking.trycloudflare.com. cloudflared's *error* messages
# mention https://api.trycloudflare.com (the service it asks for a tunnel) - never
# mistake that for the share link.
TUNNEL_URL_RE = re.compile(r"https://(?!api\.)[a-z0-9]+(?:-[a-z0-9]+)+\.trycloudflare\.com")


def _tunnel_error_hint(line):
    low = line.lower()
    if "429" in low or "too many" in low:
        return "too many tunnels requested recently - wait a few minutes and try again."
    if "no such host" in low or "lookup" in low or "dial tcp" in low or "timeout" in low:
        return "couldn't reach Cloudflare (internet/DNS problem) - check the connection and try again."
    msg = re.sub(r"^\S+\s+ERR\s+", "", line)
    return msg[:200]


class ServeStats:
    def __init__(self):
        self.sent = 0
        self.active = 0
        self.lock = threading.Lock()
        self.last_sent, self.last_t = 0, time.time()

    def add(self, n):
        with self.lock:
            self.sent += n

    def conn(self, delta):
        with self.lock:
            self.active += delta

    def sample(self):
        """(total sent, current speed, active connections)."""
        now = time.time()
        with self.lock:
            sent, active = self.sent, self.active
        speed = (sent - self.last_sent) / max(now - self.last_t, 1e-6)
        self.last_sent, self.last_t = sent, now
        return sent, speed, active


def make_handler(source, url_path, name, stats):
    quoted_name = urllib.parse.quote(name)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "shardrip"
        sys_version = ""

        def log_message(self, *args):  # keep the console clean
            pass

        def do_HEAD(self):
            self.respond(head=True)

        def do_GET(self):
            self.respond(head=False)

        def error(self, code, extra=None):
            self.send_response(code)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def respond(self, head):
            # Only the exact secret path is served; everything else is 404.
            if urllib.parse.unquote(self.path.split("?")[0]) != url_path:
                return self.error(404)

            size = source.size
            start, end, status = 0, size - 1, 200
            rng = self.headers.get("Range")
            if rng:
                m = re.fullmatch(r"\s*bytes=(\d*)-(\d*)\s*", rng)
                if not m or (m.group(1) == "" and m.group(2) == ""):
                    return self.error(416, {"Content-Range": f"bytes */{size}"})
                if m.group(1) == "":  # suffix range: last N bytes
                    start = max(0, size - int(m.group(2)))
                else:
                    start = int(m.group(1))
                    if m.group(2):
                        end = min(int(m.group(2)), size - 1)
                if start >= size or start > end:
                    return self.error(416, {"Content-Range": f"bytes */{size}"})
                status = 206

            length = end - start + 1 if size else 0
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quoted_name}")
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if head or not length:
                return

            stats.conn(+1)
            try:
                for data in source.iter_range(start, end):
                    self.wfile.write(data)
                    stats.add(len(data))
            finally:
                stats.conn(-1)

    return Handler


DROPPED = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError)


class QuietServer(http.server.ThreadingHTTPServer):
    """Receivers/Cloudflare routinely drop idle keep-alive connections - that's normal, not an error."""
    daemon_threads = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], DROPPED):
            return
        super().handle_error(request, client_address)


class Share:
    """One shared file: HTTP server + optional tunnel + optional Lock."""

    def __init__(self, path, ui, port=8080, tunnel=True, password=None):
        self.path = os.path.abspath(path)
        self.ui, self.port, self.tunnel, self.password = ui, port, tunnel, password
        self.stats = ServeStats()
        self.links, self.sha256, self.server, self.tunnel_proc = [], None, None, None
        self.lan_link = self.internet_link = self.smart_link = None

    def start(self, stop=None):
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"File not found: {self.path}")
        name = os.path.basename(self.path)
        size = os.path.getsize(self.path)
        self.ui.log(f"File: {name}  ({human(size)})")

        if self.password:
            self.ui.log("🔒 Lock on: the file is encrypted with your password as it's sent.")
            source = EncryptedSource(self.path, self.password)
            served_name = name + LOCK_EXT
        else:
            self.ui.log("Hashing (SHA256) so the receiver can verify the download...")
            self.sha256 = sha256_file(
                self.path, stop=stop,
                on_progress=lambda d, t: self.ui.status(f"Hashing... {d / t * 100:.0f}%"))
            self.ui.status_end()
            source = FileSource(self.path)
            served_name = name

        token = secrets.token_urlsafe(9)  # secret path: the link can't be guessed
        url_path = f"/{token}/{served_name}"
        link_path = f"/{token}/{urllib.parse.quote(served_name)}"
        try:
            self.server = QuietServer(("0.0.0.0", self.port),
                                      make_handler(source, url_path, served_name, self.stats))
        except OSError as e:
            raise OSError(f"Port {self.port} is in use or blocked ({e}). Try a different port.")
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

        ips = lan_ips()
        ts = tailscale_ip()
        hosts = [f"{ip}:{self.port}" for ip in ips] + ([f"{ts}:{self.port}"] if ts else [])
        self.lan_link = f"http://{ips[0]}:{self.port}{link_path}"
        self.links = [("Same network (LAN)", self.lan_link)]
        self.links += [("Same network (other adapter)", f"http://{ip}:{self.port}{link_path}") for ip in ips[1:]]
        if ts:
            self.links.append(("Tailscale", f"http://{ts}:{self.port}{link_path}"))
        self.internet_link = None
        if self.tunnel:
            if stop is not None and stop.is_set():
                raise Stopped()
            self.ui.log("Opening a public Cloudflare tunnel (no port forwarding needed)...")
            self.tunnel_proc, public = start_tunnel(self.port, self.ui)
            if public:
                self.internet_link = public + link_path
                self.links.insert(0, ("Internet only", self.internet_link))
            else:
                self.ui.log("Tunnel didn't start. LAN/Tailscale links still work.")
        # The smart link: local network when the receiver is on it, internet otherwise.
        self.smart_link = make_smart_link(self.internet_link or self.lan_link, hosts)
        if self.smart_link not in (self.internet_link, self.lan_link):
            self.links.insert(0, ("Smart link - Wi-Fi when nearby, internet otherwise", self.smart_link))
        return self

    @property
    def main_link(self):
        return self.links[0][1] if self.links else ""

    @property
    def qr_links(self):
        """[(key, button text, caption, link)] for the QR code switcher."""
        if self.smart_link == self.lan_link:
            caption = "Same Wi-Fi/network only"
        elif self.internet_link:
            caption = "Works anywhere - uses Wi-Fi when nearby"
        else:
            caption = "Same network - tries every address"
        out = [("auto", "Auto", caption, self.main_link)]
        if self.smart_link != self.lan_link:
            out.append(("lan", "Same network", "Same Wi-Fi/network only (fastest)", self.lan_link))
        if self.internet_link and self.smart_link != self.internet_link:
            out.append(("internet", "Internet", "Internet link only", self.internet_link))
        return out

    @property
    def receiver_cmd(self):
        cmd = f'python shardrip.py "{self.main_link}"'
        return cmd + (f" --sha256 {self.sha256}" if self.sha256 else "")

    def stop(self):
        if self.tunnel_proc:
            self.tunnel_proc.terminate()
            self.tunnel_proc = None
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


# ============================================================================
# Self-test (used to check a packaged Shardrip.exe has everything it needs)
# ============================================================================

class NullUI:
    def log(self, msg): pass
    def status(self, msg): pass
    def status_end(self): pass
    def confirm(self, question): return False
    def ask_password(self): return None
    def start_progress(self, total, already=0, label=""): return Progress(total, already, label)


def self_test():
    """Check the important parts work. Returns a list of 'PASS ...' / 'FAIL ...' lines."""
    import tempfile
    results = []

    def check(name, fn):
        try:
            fn()
            results.append(f"PASS {name}")
        except Exception as e:
            results.append(f"FAIL {name}: {e!r}")

    check(f"shardrip {VERSION} loaded", lambda: None)
    check("https download (requests + certificates)",
          lambda: requests.get("https://api.github.com", timeout=30, headers=UA).raise_for_status())
    check("qr code", lambda: qr_terminal(qr_encode("https://example.com/shardrip-selftest")))

    def scanner_lib():
        if not jsqr_source().startswith("(function"):
            raise ValueError("embedded jsQR failed its checksum")

    check("qr scanner library (jsQR)", scanner_lib)

    def lock_roundtrip():
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "a.bin")
            data = os.urandom(3 * 1024 * 1024 + 123)
            with open(src, "wb") as f:
                f.write(data)
            es = EncryptedSource(src, "selftest-pw")
            enc = os.path.join(d, "a.bin" + LOCK_EXT)
            with open(enc, "wb") as f:
                for piece in es.iter_range(0, es.size - 1):
                    f.write(piece)
            out = os.path.join(d, "b.bin")
            decrypt_file(enc, out, "selftest-pw", NullUI())
            with open(out, "rb") as f:
                assert f.read() == data, "decrypted data differs"
            try:
                decrypt_file(enc, out + "2", "wrong", NullUI())
                raise AssertionError("wrong password was accepted")
            except WrongPassword:
                pass

    check("lock encrypt/decrypt (cryptography)", lock_roundtrip)

    def qr_reader():
        import numpy as np
        link = "https://example-test-words.trycloudflare.com/AbC123/file.zip.shardlock"
        m = qr_encode(link)
        n, q, px = len(m), 4, 6
        img = np.full(((n + 2 * q) * px, (n + 2 * q) * px), 255, np.uint8)
        for y in range(n):
            for x in range(n):
                if m[y][x]:
                    img[(y + q) * px:(y + q + 1) * px, (x + q) * px:(x + q + 1) * px] = 0
        if qr_from_bgr(img) != link:
            raise AssertionError("couldn't read back a test QR image")

    check("qr scan / upload reader (OpenCV)", qr_reader)

    def smart_links():
        base = "https://example-test-words.trycloudflare.com/AbC123/my%20file.zip.shardlock"
        smart = make_smart_link(base, ["10.217.17.126:8080", "192.168.1.250:8080", "8.8.8.8:80", "bad"])
        b, local = split_smart_link(smart)
        assert b == base, b
        assert local == ["http://10.217.17.126:8080/AbC123/my%20file.zip.shardlock",
                         "http://192.168.1.250:8080/AbC123/my%20file.zip.shardlock"], local  # public IP dropped
        assert url_filename(smart) == "my file.zip.shardlock"
        links = Links([base], local, local[0])
        assert links.pick(0, 0) == local[0]
        links.failed(local[0])
        assert links.pick(0, 0) == base, "didn't switch to the internet link"

    check("smart links (same network first, internet fallback)", smart_links)

    def tk_window():
        import tkinter
        r = tkinter.Tk()
        r.withdraw()
        r.update()
        r.destroy()

    check("window toolkit (tkinter)", tk_window)
    return results


# ============================================================================
# Console (terminal) front-end
# ============================================================================

class ConsoleUI:
    def log(self, msg):
        print(msg)

    def status(self, msg):
        sys.stdout.write("\r  " + msg + "    ")
        sys.stdout.flush()

    def status_end(self):
        print()

    def confirm(self, question):
        try:
            return input(f"{question} (y/N): ").strip().lower() in ("y", "yes")
        except EOFError:
            return False

    def ask_password(self):
        try:
            return getpass.getpass("Password: ")
        except EOFError:
            return None

    def start_progress(self, total, already=0, label=""):
        p = Progress(total, already, label)

        def draw():
            done, total_, speed, eta, pct = p.snapshot()
            bar = "#" * int(pct / 4)
            pre = f"{label}: " if label else ""
            sys.stdout.write(f"\r{pre}[{bar:<25}] {pct:5.1f}%  {human(done)}/{human(total_)}  "
                             f"{human(speed)}/s ({speed * 8 / 1e6:.0f} Mbps)  ETA {fmt_eta(eta)}  ")
            sys.stdout.flush()

        def run():
            while not p.finished.wait(0.5):
                draw()
            draw()
            print()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        p.after_finish = lambda: t.join(2)
        return p


def cli_download(urls, output, connections, chunk_mb, sha256, password, overwrite, via="auto"):
    ui = ConsoleUI()
    out = output or url_filename(urls[0])
    try:
        return download(urls, out, ui, connections, chunk_mb, sha256, password, overwrite, via=via) is not None
    except KeyboardInterrupt:
        os._exit(1)  # progress is saved; kill worker threads immediately


def cli_serve(path, port, tunnel, password, show_qr=True):
    ui = ConsoleUI()
    share = Share(path, ui, port, tunnel, password)
    share.start()

    print()
    print("=" * 64)
    print("  ⚡ SHARING - send the receiver one of these links:")
    print("=" * 64)
    for label, link in share.links:
        print(f"  {label}:\n    {link}")
    if share.sha256:
        print(f"\n  SHA256: {share.sha256}")
    print("\n  Receiver runs:")
    print(f"    {share.receiver_cmd}")
    if password:
        print("  (they'll be asked for the password, or can add --password)")
        print(f"\n  🔒 PASSWORD: {password}")
        print("     Send it SEPARATELY from the link (e.g. text the link, call with the password).")
        print("     A browser download gives a scrambled .shardlock file - receivers need Shardrip.")
    else:
        print("  (or opens the link in a browser - slower, single connection)")
    print("=" * 64)
    if show_qr:
        try:
            print("  Scan to open the link on a phone:\n")
            print(qr_terminal(qr_encode(share.main_link)))
        except Exception as e:
            print(f"  (QR unavailable: {e})")
        print("=" * 64)
    print("  Anyone with the link can download while this window is open.\n")

    try:
        while True:
            time.sleep(1)
            sent, speed, active = share.stats.sample()
            sys.stdout.write(f"\r  Sent {human(sent)}  |  {human(speed)}/s ({speed * 8 / 1e6:.0f} Mbps)  |  "
                             f"{active} active connection(s)  |  Ctrl+C to stop   ")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        share.stop()
    print("Sharing stopped.")
    return True


# ============================================================================
# Interactive prompts
# ============================================================================

def ask(prompt, default=None, cast=str, valid=None):
    """Prompt with an optional default; re-ask until the answer is valid."""
    hint = f" [{default}]" if default not in (None, "") else ""
    while True:
        ans = input(f"  {prompt}{hint}: ").strip().strip('"')
        if not ans:
            if default is not None:
                return default
            print("    ↳ Required.")
            continue
        try:
            val = cast(ans)
            if valid is None or valid(val):
                return val
        except ValueError:
            pass
        print("    ↳ Invalid, try again.")


def _tk_dialog(kind, default=""):
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if kind == "folder":
            res = filedialog.askdirectory(initialdir=default, title="Choose where to save the download")
        else:
            res = filedialog.askopenfilename(title="Choose a file to send")
        root.destroy()
        return res or default
    except Exception:
        print("    ↳ Picker unavailable.")
        return default


def interactive():
    """Ask for everything instead of using command-line args."""
    print("=" * 56)
    print(f"  ⚡ SHARDRIP {VERSION} - multi-connection downloader")
    print("=" * 56)
    print("  1) Download a file")
    print("  2) Send a file to someone")
    print("  3) Open the app (window)" + ("  [not available on Android - use 4]" if IS_ANDROID else ""))
    print("  4) Open in your web browser (works on phones too)")
    mode = ask("Choose", "1", str, lambda v: v in ("1", "2", "3", "4"))

    if mode == "3":
        if IS_ANDROID:
            return argparse.Namespace(gui=False, web=True, lan=False, web_port=7777)
        return argparse.Namespace(gui=True, web=False)
    if mode == "4":
        return argparse.Namespace(gui=False, web=True, lan=False, web_port=7777)

    if mode == "2":
        while True:
            path = ask("File to send (drag it in, or B = browse)")
            if path.lower() == "b":
                path = _tk_dialog("file")
                print(f"    ↳ {path or '(cancelled)'}")
            if path and os.path.isfile(path):
                break
            print("    ↳ File not found, try again.")
        port = ask("Port", 8080, int, lambda n: 1024 <= n <= 65535)
        public = ask("Public internet link via Cloudflare? (Y/n)", "y", str,
                     lambda v: v.lower() in ("y", "n", "yes", "no"))
        lock = input("  Lock with a password? (Enter = no, G = generate one, or type your own): ").strip()
        password = gen_password() if lock.lower() == "g" else (lock or None)
        print()
        return argparse.Namespace(gui=False, web=False, serve=path, port=port, no_tunnel=public.lower().startswith("n"),
                                  password=password, lock=False, no_qr=False)

    url = ask("Download URL")
    mirrors = []
    while True:
        m = input("  Extra mirror URL (Enter to skip): ").strip().strip('"')
        if not m:
            break
        mirrors.append(m)

    downloads = default_download_dir()
    folder = ask("Save folder (B = browse)", downloads)
    if folder.lower() == "b":
        folder = _tk_dialog("folder", downloads)
        print(f"    ↳ {folder}")
    os.makedirs(folder, exist_ok=True)

    name = ask("File name", url_filename(url))
    conns = ask("Connections (1-32)", 16, int, lambda n: 1 <= n <= 32)
    sha = input("  SHA256 to verify (Enter to skip): ").strip() or None
    if sha and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
        print("    ↳ That doesn't look like a SHA256 (64 hex chars) - skipping verification.")
        sha = None

    print()
    return argparse.Namespace(gui=False, web=False, serve=None, urls=[url] + mirrors, output=os.path.join(folder, name),
                              connections=conns, chunk_mb=16, sha256=sha, password=None, overwrite=False)


# ============================================================================
# GUI (tkinter - built into Python)
# ============================================================================

# ============================================================================
# QR reading from images / webcam (OpenCV) - used by the native app's Scan QR
# ============================================================================

def _cv2():
    """Import OpenCV (installs opencv-python-headless on first use when running from Python)."""
    return ensure_package("opencv-python-headless", "cv2")


def qr_from_bgr(img):
    """Find and decode a QR code in a BGR/grey image. Returns the text or None."""
    cv2 = _cv2()
    import numpy as np
    if img is None or getattr(img, "size", 0) == 0:
        return None
    gray = img if img.ndim == 2 else cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape[:2]
    candidates = [gray]
    if max(h, w) < 900:
        candidates.append(cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC))
    if max(h, w) > 2200:
        s = 1600 / max(h, w)
        candidates.append(cv2.resize(gray, None, fx=s, fy=s, interpolation=cv2.INTER_AREA))
    candidates.append(cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])
    candidates.append(255 - gray)  # light-on-dark QR codes
    detectors = [cv2.QRCodeDetector()]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.append(cv2.QRCodeDetectorAruco())
    for c in candidates:
        c = np.ascontiguousarray(c)
        for d in detectors:
            try:
                text, _, _ = d.detectAndDecode(c)
            except Exception:
                text = ""
            if text:
                return text
    return None


def qr_from_image_file(path):
    """Decode a QR code from an image file (screenshot/photo). Handles non-English paths."""
    cv2 = _cv2()
    import numpy as np
    data = np.fromfile(path, dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("That file isn't an image Shardrip can read")
    return qr_from_bgr(img)


# ============================================================================
# Native app (tkinter) - this is what Shardrip.exe opens. No browser involved.
# ============================================================================

THEME = dict(bg="#0a0f1a", top="#0b1220", card="#0f1828", line="#1d2a40", input="#131e31", input_line="#22314b",
             fg="#e7eef8", head="#f3f7fd", muted="#8ea3bf", label="#6f86a6", accent="#00c2f5", accent2="#33d0fa",
             accent_dim="#0b5f78", ink="#03131f", danger="#ff6b6b", amber="#fbbf24", log="#0a1220",
             hover="#18263c")


def _dark_title_bar(win):
    """Windows 10/11: make the window's title bar dark to match the app."""
    if not IS_WIN:
        return
    try:
        import ctypes
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        on = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (new / old builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(on), ctypes.sizeof(on)) == 0:
                break
    except Exception:
        pass


def gui_main(_test_hook=None):
    import tkinter as tk
    from tkinter import filedialog, ttk

    T = THEME
    UI_FONT = ("Segoe UI", 10)
    UI_BOLD = ("Segoe UI Semibold", 10)
    HEAD_FONT = ("Segoe UI Semibold", 15)
    LABEL_FONT = ("Consolas", 8)
    MONO = ("Consolas", 9)

    class GuiUI:
        """Lets the engines (running in worker threads) talk to the window safely."""

        def __init__(self, app, tab):
            self.app, self.tab = app, tab

        def log(self, msg):
            self.app.q.put(("log", self.tab, msg))

        def status(self, msg):
            self.app.q.put(("status", self.tab, msg))

        def status_end(self):
            self.app.q.put(("status", self.tab, ""))

        def confirm(self, question):
            return self.app.call_main(lambda: self.app.dialog(question, kind="confirm"))

        def ask_password(self):
            return self.app.call_main(lambda: self.app.dialog(
                "This file is password-locked. Enter the password:", kind="password"))

        def start_progress(self, total, already=0, label=""):
            p = Progress(total, already, label)
            self.app.q.put(("progress", self.tab, p))
            return p

    # ---------- small widget helpers ----------
    def label(parent, text):
        return tk.Label(parent, text=text.upper(), bg=T["card"], fg=T["label"], font=LABEL_FONT, anchor="w")

    def entry(parent, var, show=None, mono=False):
        e = tk.Entry(parent, textvariable=var, show=show or "", bg=T["input"], fg=T["fg"],
                     insertbackground=T["fg"], relief="flat", font=MONO if mono else UI_FONT,
                     highlightthickness=1, highlightbackground=T["input_line"], highlightcolor=T["accent"],
                     disabledbackground=T["input"], disabledforeground=T["label"],
                     readonlybackground=T["input"], selectbackground=T["accent_dim"], selectforeground=T["fg"])
        return e

    class Btn(tk.Label):
        """Flat button that looks the same on every Windows version (tk.Button ignores colours on Windows)."""

        def __init__(self, parent, text, command, kind="secondary", width=None):
            super().__init__(parent, text=text, font=UI_BOLD, cursor="hand2", padx=14, pady=8,
                             highlightthickness=1, width=width or 0)
            self.command, self.kind, self.enabled = command, kind, True
            self.bind("<Button-1>", lambda e: self.enabled and self.command())
            self.bind("<Enter>", lambda e: self._paint(hover=True))
            self.bind("<Leave>", lambda e: self._paint())
            self._paint()

        def _paint(self, hover=False):
            if self.kind == "primary":
                if self.enabled:
                    bg = T["accent2"] if hover else T["accent"]
                    self.configure(bg=bg, fg=T["ink"], highlightbackground=bg, cursor="hand2")
                else:
                    self.configure(bg=T["accent_dim"], fg="#6fa9bd", highlightbackground=T["accent_dim"],
                                   cursor="arrow")
            elif self.kind == "stop":
                if self.enabled:
                    self.configure(bg=T["hover"] if hover else T["card"], fg=T["danger"],
                                   highlightbackground=T["danger"] if hover else "#5a2a35", cursor="hand2")
                else:
                    self.configure(bg=T["card"], fg="#3d4f6a", highlightbackground=T["line"], cursor="arrow")
            else:
                if self.enabled:
                    self.configure(bg=T["hover"] if hover else T["input"], fg=T["accent"] if hover else T["muted"],
                                   highlightbackground=T["accent"] if hover else T["input_line"], cursor="hand2")
                else:
                    self.configure(bg=T["input"], fg="#3d4f6a", highlightbackground=T["line"], cursor="arrow")

        def set_enabled(self, on):
            self.enabled = bool(on)
            self._paint()

        # compatibility with code/tests that read button state
        def __getitem__(self, key):
            if key == "state":
                return "normal" if self.enabled else "disabled"
            return super().__getitem__(key)

    def segmented(parent, var, options, small=False):
        """Row of toggle buttons bound to a StringVar: options = [(value, text)]."""
        box = tk.Frame(parent, bg=T["card"])
        btns = {}

        def paint(*_):
            for k, b in btns.items():
                on = var.get() == k
                b.configure(bg="#0c2433" if on else T["input"], fg=T["accent"] if on else T["muted"],
                            highlightbackground=T["accent"] if on else T["input_line"])

        for k, text in options:
            b = tk.Label(box, text=text, font=("Segoe UI", 8) if small else UI_FONT, padx=8 if small else 12,
                         pady=3 if small else 7, cursor="hand2", highlightthickness=1)
            b.pack(side="left", padx=(0, 4 if small else 6))
            b.bind("<Button-1>", lambda e, k=k: var.set(k))
            btns[k] = b
        var.trace_add("write", paint)
        paint()
        return box

    def check(parent, text, var, command=None):
        return tk.Checkbutton(parent, text=text, variable=var, command=command, bg=T["card"], fg=T["fg"],
                              activebackground=T["card"], activeforeground=T["fg"], selectcolor=T["input"],
                              font=UI_FONT, highlightthickness=0, bd=0, cursor="hand2", anchor="w")

    def log_box(parent, height):
        wrap = tk.Frame(parent, bg=T["line"])
        txt = tk.Text(wrap, height=height, bg=T["log"], fg="#9fb2cc", font=MONO, relief="flat", wrap="word",
                      state="disabled", padx=10, pady=8, insertbackground=T["fg"], highlightthickness=0,
                      selectbackground=T["accent_dim"])
        sb = ttk.Scrollbar(wrap, orient="vertical", command=txt.yview, style="Dark.Vertical.TScrollbar")
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", padx=(0, 1), pady=1)
        txt.pack(side="left", fill="both", expand=True, padx=(1, 0), pady=1)
        return wrap, txt

    class Tabs:
        """Top-bar tabs (Download / Send). .select(frame) works like a ttk.Notebook."""

        def __init__(self, app):
            self.app, self.frames, self.buttons = app, [], []

        def add(self, frame, button):
            self.frames.append(frame)
            self.buttons.append(button)

        def select(self, frame):
            for f, b in zip(self.frames, self.buttons):
                on = f is frame
                if on:
                    f.pack(fill="both", expand=True)
                else:
                    f.pack_forget()
                b.configure(fg=T["accent"] if on else T["muted"],
                            highlightbackground=T["accent"] if on else T["input_line"],
                            bg="#0c2433" if on else T["top"])

    class App:
        def __init__(self, root):
            self.root = root
            self.q = queue.Queue()
            self.prog = {"dl": None, "send": None}
            self.dl_stop = None
            self._row_vars = []
            self.share = None
            self.send_stop = None
            self.scanner = None
            root.title("Shardrip")
            root.configure(bg=T["bg"])
            root.geometry("860x900")
            root.minsize(640, 640)
            _dark_title_bar(root)

            style = ttk.Style()
            style.theme_use("clam")
            style.configure("Shard.Horizontal.TProgressbar", background=T["accent"], troughcolor=T["input"],
                            bordercolor=T["line"], lightcolor=T["accent"], darkcolor=T["accent"], thickness=10)
            style.configure("Dark.Vertical.TScrollbar", background=T["input_line"], troughcolor=T["log"],
                            bordercolor=T["log"], arrowcolor=T["muted"], lightcolor=T["input_line"],
                            darkcolor=T["input_line"], gripcount=0)
            style.map("Dark.Vertical.TScrollbar", background=[("active", "#2f4466")])

            # top bar
            top = tk.Frame(root, bg=T["top"], height=56, highlightthickness=0)
            top.pack(fill="x")
            tk.Frame(root, bg=T["line"], height=1).pack(fill="x")
            logo = tk.Canvas(top, width=30, height=30, bg=T["top"], highlightthickness=0)
            logo.create_rectangle(0, 0, 30, 30, fill="#1b7fe8", outline="")
            logo.create_polygon(0, 0, 30, 0, 0, 30, fill=T["accent"], outline="")
            logo.create_text(15, 15, text="⚡", font=("Segoe UI Emoji", 12), fill="white")
            logo.pack(side="left", padx=(18, 10), pady=13)
            tk.Label(top, text="Shardrip", bg=T["top"], fg=T["head"], font=("Segoe UI Semibold", 12)).pack(side="left")
            tk.Label(top, text=f"v{VERSION}", bg=T["top"], fg=T["label"], font=MONO).pack(side="right", padx=18)

            body = tk.Frame(root, bg=T["bg"])
            body.pack(fill="both", expand=True)
            self.card = tk.Frame(body, bg=T["card"], highlightthickness=1, highlightbackground=T["line"])
            self.card.pack(fill="both", expand=True, padx=26, pady=22)
            inner = tk.Frame(self.card, bg=T["card"])
            inner.pack(fill="both", expand=True, padx=24, pady=20)
            self.dl_tab = tk.Frame(inner, bg=T["card"])
            self.send_tab = tk.Frame(inner, bg=T["card"])

            self.nb = Tabs(self)
            for frame, text in ((self.dl_tab, "⬇  Download"), (self.send_tab, "⬆  Send")):
                b = tk.Label(top, text=text, font=("Segoe UI Semibold", 9), padx=12, pady=4, cursor="hand2",
                             highlightthickness=1, bg=T["top"])
                b.pack(side="left", padx=(12 if frame is self.dl_tab else 6, 0))
                b.bind("<Button-1>", lambda e, fr=frame: self.nb.select(fr))
                self.nb.add(frame, b)

            self.build_download()
            self.build_send()
            self.nb.select(self.dl_tab)
            root.protocol("WM_DELETE_WINDOW", self.on_close)
            root.after(100, self.poll)

        # ---------- helpers ----------
        def call_main(self, fn):
            if threading.current_thread() is threading.main_thread():
                return fn()
            ev, box = threading.Event(), {}
            self.q.put(("call", fn, ev, box))
            ev.wait()
            return box.get("r")

        def copy(self, text):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            self.flash("Copied ✓")

        def flash(self, text, ms=1800):
            """Small toast at the bottom of the window."""
            t = tk.Label(self.root, text=text, bg=T["card"], fg=T["fg"], font=UI_FONT, padx=16, pady=8,
                         highlightthickness=1, highlightbackground=T["accent"])
            t.place(relx=0.5, rely=1.0, y=-26, anchor="s")
            self.root.after(ms, t.destroy)

        @staticmethod
        def log_to(widget, msg):
            widget.configure(state="normal")
            widget.insert("end", msg + "\n")
            widget.see("end")
            widget.configure(state="disabled")

        def heading(self, parent, title, sub):
            tk.Label(parent, text=title, bg=T["card"], fg=T["head"], font=HEAD_FONT, anchor="w").pack(fill="x")
            tk.Label(parent, text=sub, bg=T["card"], fg=T["muted"], font=UI_FONT, anchor="w").pack(fill="x", pady=(2, 4))

        def field(self, parent, text, widget, extra=None, pady=(12, 0)):
            box = tk.Frame(parent, bg=T["card"])
            label(box, text + ":").pack(fill="x", pady=(0, 5))
            row = tk.Frame(box, bg=T["card"])
            row.pack(fill="x")
            widget.pack(in_=row, side="left", fill="x", expand=True, ipady=7)
            widget.lift(row)  # created before `row`, so raise it or the frame hides it
            if extra is not None:
                extra.pack(in_=row, side="left", padx=(8, 0))
                extra.lift(row)
            box.pack(fill="x", pady=pady)
            return box

        def dialog(self, text, kind="confirm"):
            """Dark modal dialog. kind: confirm -> bool, password -> str/None."""
            d = tk.Toplevel(self.root, bg=T["card"])
            d.title("Shardrip")
            d.transient(self.root)
            d.resizable(False, False)
            _dark_title_bar(d)
            res = {"v": None if kind == "password" else False}
            tk.Label(d, text=text, bg=T["card"], fg=T["fg"], font=UI_FONT, wraplength=380, justify="left").pack(
                padx=22, pady=(20, 10), anchor="w")
            pw = tk.StringVar()
            if kind == "password":
                e = entry(d, pw, show="•")
                e.pack(fill="x", padx=22, ipady=7)
                e.focus_set()
            row = tk.Frame(d, bg=T["card"])
            row.pack(fill="x", padx=22, pady=(16, 20))

            def ok(*_):
                res["v"] = pw.get() if kind == "password" else True
                d.destroy()

            def cancel(*_):
                d.destroy()

            Btn(row, "Unlock" if kind == "password" else "Yes", ok, "primary").pack(side="left", fill="x", expand=True)
            Btn(row, "Cancel" if kind == "password" else "No", cancel).pack(side="left", fill="x", expand=True, padx=(8, 0))
            d.bind("<Return>", ok)
            d.bind("<Escape>", cancel)
            d.update_idletasks()
            x = self.root.winfo_rootx() + (self.root.winfo_width() - d.winfo_width()) // 2
            y = self.root.winfo_rooty() + (self.root.winfo_height() - d.winfo_height()) // 3
            d.geometry(f"+{max(x, 0)}+{max(y, 0)}")
            d.grab_set()
            self.root.wait_window(d)
            return res["v"]

        # ---------- download tab ----------
        def build_download(self):
            f = self.dl_tab
            self.heading(f, "Download a file", "Paste a link, or scan / upload a Shardrip QR code.")
            self.url = tk.StringVar()
            self.mirrors = tk.StringVar()
            self.folder = tk.StringVar(value=default_download_dir())
            self.fname = tk.StringVar()
            self.conns = tk.StringVar(value="16")
            self.sha = tk.StringVar()
            self.dl_pw = tk.StringVar()
            self.via = tk.StringVar(value="auto")
            self._name_auto = True

            self.field(f, "Download URL", entry(f, self.url), Btn(f, "📷  Scan QR", self.open_scanner))
            self.field(f, "Save to", entry(f, self.folder), Btn(f, "Browse", self.pick_folder))
            grid = tk.Frame(f, bg=T["card"])
            grid.pack(fill="x")
            grid.columnconfigure(0, weight=1, uniform="g")
            grid.columnconfigure(1, weight=1, uniform="g")
            cells = []
            name_entry = entry(grid, self.fname)
            name_entry.bind("<Key>", lambda e: setattr(self, "_name_auto", False))
            self.dl_pw_entry = entry(grid, self.dl_pw, show="•")
            for i, (t, w) in enumerate((("File name", name_entry), ("Connections", entry(grid, self.conns)),
                                        ("Password (locked files)", self.dl_pw_entry),
                                        ("SHA256 (optional)", entry(grid, self.sha, mono=True)))):
                cell = tk.Frame(grid, bg=T["card"])
                cell.grid(row=i // 2, column=i % 2, sticky="ew", padx=(0, 7) if i % 2 == 0 else (7, 0))
                self.field(cell, t, w)
                cells.append(cell)
            self.field(f, "Extra mirrors (optional, separated by spaces)", entry(f, self.mirrors))
            via_row = tk.Frame(f, bg=T["card"])
            via_box = segmented(via_row, self.via, [(k, VIA[k]) for k in VIA])
            via_box.pack(side="left")
            self.via_hint = tk.Label(via_row, bg=T["card"], fg=T["muted"], font=("Segoe UI", 9), anchor="w")
            self.via_hint.pack(side="left", padx=(6, 0))
            self.field(f, "Connect via (for Shardrip smart links)", via_row)
            self.via.trace_add("write", self.via_changed)
            self.via_changed()
            self.url.trace_add("write", self.url_changed)

            self.dl_start = Btn(f, "⬇  Start download", self.start_download, "primary")
            self.dl_start.pack(fill="x", pady=(20, 0))
            self.dl_stopbtn = Btn(f, "■  Stop", self.stop_download, "stop")
            self.dl_stopbtn.pack(fill="x", pady=(8, 0))
            self.dl_stopbtn.set_enabled(False)

            self.dl_bar = ttk.Progressbar(f, maximum=100, style="Shard.Horizontal.TProgressbar")
            self.dl_bar.pack(fill="x", pady=(18, 0))
            self.dl_info = tk.Label(f, text="Ready.", bg=T["card"], fg=T["muted"], font=UI_FONT, anchor="w",
                                    justify="left", wraplength=740)
            self.dl_info.pack(fill="x", pady=(8, 0))
            wrap, self.dl_log = log_box(f, 7)
            wrap.pack(fill="both", expand=True, pady=(12, 0))

        def via_changed(self, *_):
            self.via_hint.configure(text={
                "auto": "same Wi-Fi as the sender → direct & fast, otherwise internet",
                "lan": "only over the local network - fails away from it",
                "internet": "always through the internet link"}[self.via.get()])

        def url_changed(self, *_):
            if self._name_auto:
                u = self.url.get().strip()
                self.fname.set(url_filename(u) if u else "")

        def pick_folder(self):
            d = filedialog.askdirectory(initialdir=self.folder.get(), parent=self.root)
            if d:
                self.folder.set(d)

        def start_download(self):
            url = self.url.get().strip().strip('"')
            if not url.lower().startswith(("http://", "https://")):
                self.flash("Paste a download link (or scan a QR) first")
                return
            urls = [url] + [m for m in self.mirrors.get().split() if m]
            out = os.path.join(os.path.expanduser(self.folder.get().strip()),
                               self.fname.get().strip() or url_filename(url))
            sha = self.sha.get().strip() or None
            if sha and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
                self.flash("That SHA256 doesn't look right (64 hex characters)")
                return
            try:
                conns = max(1, min(32, int(self.conns.get())))
            except ValueError:
                conns = 16
            pw = self.dl_pw.get() or None
            via = self.via.get()
            self.dl_stop = threading.Event()
            self.dl_start.set_enabled(False)
            self.dl_stopbtn.set_enabled(True)
            self.dl_bar["value"] = 0
            self.dl_info.configure(text="Starting…")
            ui = GuiUI(self, "dl")

            def work():
                try:
                    res = download(urls, out, ui, conns, 16, sha, pw, False, self.dl_stop, via=via)
                except Exception as e:
                    ui.log(f"❌ Error: {e}")
                    res = None
                self.q.put(("dl_done", res))

            threading.Thread(target=work, daemon=True).start()

        def stop_download(self):
            if self.dl_stop:
                self.dl_stop.set()
                self.dl_info.configure(text="Stopping…")

        # ---------- QR scanner (webcam + image upload) ----------
        def use_scanned(self, text):
            if not text or not text.lower().startswith(("http://", "https://")):
                self.flash("That QR code isn't a download link")
                return False
            self.nb.select(self.dl_tab)
            self._name_auto = True
            self.url.set(text.strip())
            locked = LOCK_EXT in urllib.parse.unquote(text.split("?")[0])
            if locked:
                self.dl_info.configure(text="🔒 Locked file - enter the password, then press Start download.")
                self.dl_pw_entry.focus_set()
                self.flash("🔒 Locked file - enter the password, then Start")
            else:
                self.dl_info.configure(text="Link filled ✓ - press Start download.")
                self.flash("Link filled ✓")
            return True

        def upload_qr_image(self, path=None):
            path = path or filedialog.askopenfilename(
                parent=self.scanner or self.root, title="Choose a screenshot or photo of the QR code",
                filetypes=[("Images", "*.png *.jpg *.jpeg *.webp *.bmp *.gif *.tif *.tiff"), ("All files", "*.*")])
            if not path:
                return False
            try:
                text = qr_from_image_file(path)
            except Exception as e:
                self.flash(f"Couldn't read that image: {e}")
                return False
            if not text:
                self.flash("No QR code found in that image - try a clearer screenshot")
                return False
            self.close_scanner()
            return self.use_scanned(text)

        def open_scanner(self):
            if self.scanner:
                self.scanner.lift()
                return
            try:
                cv2 = _cv2()
            except Exception as e:
                self.flash(f"QR scanning isn't available: {e}")
                return
            d = tk.Toplevel(self.root, bg=T["card"])
            d.title("Scan or upload a QR code")
            d.transient(self.root)
            d.resizable(False, False)
            _dark_title_bar(d)
            self.scanner = d
            tk.Label(d, text="Scan or upload a Shardrip QR code", bg=T["card"], fg=T["head"],
                     font=("Segoe UI Semibold", 12)).pack(anchor="w", padx=20, pady=(16, 10))
            self.cam_view = tk.Label(d, bg="#000000", width=480, height=360, text="Starting camera…",
                                     fg=T["muted"], font=UI_FONT, compound="center")
            self.cam_view.pack(padx=20)
            self.cam_hint = tk.Label(d, text="Point your camera at the QR code, or upload a screenshot / photo of it.",
                                     bg=T["card"], fg=T["muted"], font=UI_FONT, wraplength=480, justify="left")
            self.cam_hint.pack(anchor="w", padx=20, pady=(10, 0))
            row = tk.Frame(d, bg=T["card"])
            row.pack(fill="x", padx=20, pady=(14, 18))
            Btn(row, "🖼  Upload QR image", self.upload_qr_image, "primary").pack(side="left", fill="x", expand=True)
            Btn(row, "Cancel", self.close_scanner).pack(side="left", fill="x", expand=True, padx=(8, 0))
            d.protocol("WM_DELETE_WINDOW", self.close_scanner)
            d.bind("<Escape>", lambda e: self.close_scanner())
            d.update_idletasks()
            x = self.root.winfo_rootx() + (self.root.winfo_width() - d.winfo_reqwidth()) // 2
            y = self.root.winfo_rooty() + 60
            d.geometry(f"+{max(x, 0)}+{max(y, 0)}")

            self._cam = {"stop": threading.Event(), "frame": None, "result": None, "error": None}
            cam = self._cam

            def camera_thread():
                cap = None
                try:
                    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW) if IS_WIN else cv2.VideoCapture(0)
                    if not cap or not cap.isOpened():
                        cam["error"] = "No camera found."
                        return
                    n = 0
                    while not cam["stop"].is_set():
                        ok, frame = cap.read()
                        if not ok or frame is None:
                            time.sleep(0.05)
                            continue
                        h, w = frame.shape[:2]
                        s = 480 / max(w, 1)
                        small = cv2.resize(frame, (480, max(1, int(h * s))))
                        ok2, png = cv2.imencode(".png", small)
                        if ok2:
                            cam["frame"] = png.tobytes()
                        n += 1
                        if n % 3 == 0:
                            text = qr_from_bgr(frame)
                            if text:
                                cam["result"] = text
                                return
                except Exception as e:
                    cam["error"] = f"Couldn't open the camera ({e})."
                finally:
                    if cap is not None:
                        cap.release()

            threading.Thread(target=camera_thread, daemon=True).start()
            self.root.after(60, self._scanner_tick)

        def _scanner_tick(self):
            if not self.scanner:
                return
            cam = self._cam
            if cam["result"]:
                text = cam["result"]
                self.close_scanner()
                self.use_scanned(text)
                return
            if cam["error"]:
                self.cam_view.configure(image="", text="📷  " + cam["error"])
                self.cam_hint.configure(text=cam["error"] + " Click “Upload QR image” and pick a screenshot or "
                                                          "photo of the QR code instead.")
                return
            frame, cam["frame"] = cam["frame"], None
            if frame:
                import base64
                img = tk.PhotoImage(data=base64.b64encode(frame).decode("ascii"))
                self.cam_view.configure(image=img, text="", width=img.width(), height=img.height())
                self.cam_view.image = img
            self.root.after(60, self._scanner_tick)

        def close_scanner(self):
            if getattr(self, "_cam", None):
                self._cam["stop"].set()
            if self.scanner:
                self.scanner.destroy()
                self.scanner = None

        # ---------- send tab ----------
        def build_send(self):
            f = self.send_tab
            self.heading(f, "Send a file", "Share a file from this PC with a link - no port forwarding needed.")
            self.send_path = tk.StringVar()
            self.port = tk.StringVar(value="8080")
            self.public = tk.BooleanVar(value=True)
            self.lock = tk.BooleanVar(value=False)
            self.send_pw = tk.StringVar()

            self.field(f, "File to send", entry(f, self.send_path), Btn(f, "Browse", self.pick_file))
            row = tk.Frame(f, bg=T["card"])
            row.pack(fill="x")
            port_cell = tk.Frame(row, bg=T["card"])
            port_cell.pack(side="left")
            self.field(port_cell, "Port", entry(port_cell, self.port))
            check(row, "  Public internet link", self.public).pack(side="left", padx=(18, 0), pady=(30, 0))
            check(f, "  🔒 Lock with password", self.lock, self.lock_toggled).pack(anchor="w", pady=(14, 0))
            self.pw_row = tk.Frame(f, bg=T["card"])
            self.pw_entry = entry(self.pw_row, self.send_pw, mono=True)
            self.pw_entry.pack(side="left", fill="x", expand=True, ipady=7)
            self.gen_btn = Btn(self.pw_row, "Generate", lambda: self.send_pw.set(gen_password()))
            self.gen_btn.pack(side="left", padx=(8, 0))
            self.lock_note = tk.Label(f, text="🔒 Send the password separately from the link - e.g. text the link, "
                                              "say the password. The receiver needs Shardrip to unlock it.",
                                      bg="#1b1a12", fg=T["amber"], font=UI_FONT, justify="left", wraplength=740,
                                      anchor="w", padx=12, pady=8, highlightthickness=1, highlightbackground="#6b5420")
            self.send_actions = tk.Frame(f, bg=T["card"])
            self.send_actions.pack(fill="x")
            self.send_start = Btn(self.send_actions, "⬆  Start sharing", self.start_share, "primary")
            self.send_start.pack(fill="x", pady=(20, 0))
            self.send_stopbtn = Btn(self.send_actions, "■  Stop sharing", self.stop_share, "stop")
            self.send_stopbtn.pack(fill="x", pady=(8, 0))
            self.send_stopbtn.set_enabled(False)
            self.send_info = tk.Label(f, text="Pick a file and press Start sharing.", bg=T["card"], fg=T["muted"],
                                      font=UI_FONT, anchor="w", justify="left", wraplength=740)
            self.send_info.pack(fill="x", pady=(10, 0))

            mid = tk.Frame(f, bg=T["card"])
            mid.pack(fill="x", pady=(4, 0))
            self.links_frame = tk.Frame(mid, bg=T["card"])
            self.links_frame.pack(side="left", fill="both", expand=True)
            self.qrbox = tk.Frame(mid, bg=T["card"])
            self.qr = tk.Canvas(self.qrbox, width=200, height=200, bg="white", highlightthickness=0)
            self.qr.pack(pady=(12, 0))
            self.qr_label = tk.Label(self.qrbox, text="Scan with a phone camera", bg=T["card"], fg=T["muted"],
                                     font=("Segoe UI", 9), wraplength=210, justify="center")
            self.qr_label.pack(pady=(6, 0))
            self.qr_choice = tk.StringVar(value="auto")
            self.qr_choice.trace_add("write", self.qr_choice_changed)
            self.qr_switch = None
            wrap, self.send_log = log_box(f, 5)
            wrap.pack(fill="both", expand=True, pady=(12, 0))

        def lock_toggled(self):
            on = self.lock.get()
            if on:
                self.pw_row.pack(fill="x", pady=(10, 0), before=self.send_actions)
                self.lock_note.pack(fill="x", pady=(10, 0), before=self.send_actions)
                if not self.send_pw.get():
                    self.send_pw.set(gen_password())
            else:
                self.pw_row.pack_forget()
                self.lock_note.pack_forget()

        def pick_file(self):
            p = filedialog.askopenfilename(parent=self.root, title="Choose a file to send")
            if p:
                self.send_path.set(p)

        def clear_links(self):
            for w in self.links_frame.winfo_children():
                w.destroy()
            self._row_vars = []
            self.qr.delete("all")
            if self.qr_switch is not None:
                self.qr_switch.destroy()
                self.qr_switch = None
            self.qrbox.pack_forget()

        def add_copy_row(self, label_text, value, highlight=False, password=False):
            lab = tk.Label(self.links_frame, text=label_text.upper(), bg=T["card"],
                           fg=T["accent"] if highlight else T["label"], font=LABEL_FONT, anchor="w")
            lab.pack(fill="x", pady=(12, 5))
            row = tk.Frame(self.links_frame, bg=T["card"])
            row.pack(fill="x")
            var = tk.StringVar(value=value)
            self._row_vars.append(var)  # keep a reference, or Tk blanks the box
            e = entry(row, var, mono=True)
            e.configure(state="readonly", fg=T["amber"] if password else "#bcd0e8")
            e.pack(side="left", fill="x", expand=True, ipady=6)
            Btn(row, "Copy", lambda: self.copy(value)).pack(side="left", padx=(8, 0))

        def draw_qr(self, text):
            self.qr.delete("all")
            try:
                m = qr_encode(text)
            except Exception as e:
                self.qr_label.configure(text=f"QR unavailable: {e}")
                return
            n = len(m)
            px = max(1, 200 // (n + 6))
            off = (200 - px * n) // 2
            for y in range(n):
                for x in range(n):
                    if m[y][x]:
                        self.qr.create_rectangle(off + x * px, off + y * px, off + (x + 1) * px,
                                                 off + (y + 1) * px, fill="black", width=0)
            self.qrbox.pack(side="right", padx=(18, 0), anchor="n")

        def start_share(self):
            path = self.send_path.get().strip().strip('"')
            if not os.path.isfile(path):
                self.flash("Pick a file to send first")
                return
            pw = self.send_pw.get().strip() if self.lock.get() else None
            if self.lock.get() and not pw:
                self.flash("Enter or generate a password for the lock")
                return
            try:
                port = int(self.port.get())
            except ValueError:
                port = 8080
            self.clear_links()
            self.send_start.set_enabled(False)
            self.send_stopbtn.set_enabled(True)
            self.send_info.configure(text="Starting…")
            self.send_stop = threading.Event()
            ui = GuiUI(self, "send")
            share = Share(path, ui, port, self.public.get(), pw)

            def work():
                try:
                    share.start(self.send_stop)
                    if self.send_stop.is_set():
                        share.stop()
                        self.q.put(("share_failed", None))
                    else:
                        self.q.put(("shared", share))
                except Exception as e:
                    share.stop()
                    if not isinstance(e, Stopped):
                        ui.log(f"❌ Error: {e}")
                    self.q.put(("share_failed", None))

            threading.Thread(target=work, daemon=True).start()

        def show_share(self, share):
            self.share = share
            for i, (lab, link) in enumerate(share.links):
                self.add_copy_row(lab, link, highlight=(i == 0))
            self.add_copy_row("Receiver runs", share.receiver_cmd)
            if share.password:
                self.add_copy_row("🔒 Password - send it separately", share.password, highlight=True, password=True)
            elif share.sha256:
                self.add_copy_row("SHA256", share.sha256)
            choices = share.qr_links
            if len(choices) > 1:
                self.qr_switch = segmented(self.qrbox, self.qr_choice, [(k, t) for k, t, _, _ in choices], small=True)
                self.qr_switch.pack(pady=(8, 0))
            if self.qr_choice.get() == "auto":
                self.qr_choice_changed()
            else:
                self.qr_choice.set("auto")
            self.log_to(self.send_log, "Sharing is live ✅")

        def qr_choice_changed(self, *_):
            if not self.share:
                return
            for k, _t, caption, link in self.share.qr_links:
                if k == self.qr_choice.get():
                    self.draw_qr(link)
                    self.qr_label.configure(text=f"Scan with a phone camera\n{caption}")
                    return

        def stop_share(self):
            if self.send_stop:
                self.send_stop.set()
            share, self.share = self.share, None
            if share:
                threading.Thread(target=share.stop, daemon=True).start()
                self.log_to(self.send_log, "Sharing stopped.")
            self.send_start.set_enabled(True)
            self.send_stopbtn.set_enabled(False)
            self.send_info.configure(text="Stopped. The link no longer works.")

        # ---------- event loop ----------
        def poll(self):
            try:
                while True:
                    item = self.q.get_nowait()
                    kind = item[0]
                    if kind == "log":
                        self.log_to(self.dl_log if item[1] == "dl" else self.send_log, item[2])
                    elif kind == "status":
                        (self.dl_info if item[1] == "dl" else self.send_info).configure(text=item[2])
                    elif kind == "progress":
                        self.prog[item[1]] = item[2]
                    elif kind == "call":
                        _, fn, ev, box = item
                        try:
                            box["r"] = fn()
                        finally:
                            ev.set()
                    elif kind == "dl_done":
                        self.dl_start.set_enabled(True)
                        self.dl_stopbtn.set_enabled(False)
                        p = self.prog["dl"]
                        if p:
                            self.update_dl(p)
                        self.prog["dl"] = None
                        if item[1]:
                            self.dl_bar["value"] = 100
                            self.dl_info.configure(text=f"✅ Done: {item[1]}")
                        else:
                            self.dl_info.configure(text="Stopped / not completed - see the log below.")
                    elif kind == "shared":
                        self.show_share(item[1])
                    elif kind == "share_failed":
                        self.send_start.set_enabled(True)
                        self.send_stopbtn.set_enabled(False)
                        self.send_info.configure(text="Not sharing - see the log below.")
            except queue.Empty:
                pass
            p = self.prog["dl"]
            if p:
                self.update_dl(p)
            if self.share:
                sent, speed, active = self.share.stats.sample()
                self.send_info.configure(
                    text=f"Sharing ✅   Sent {human(sent)}  ·  {human(speed)}/s ({speed * 8 / 1e6:.0f} Mbps)"
                         f"  ·  {active} active connection(s)")
            self.root.after(250 if self.share else 100, self.poll)

        def update_dl(self, p):
            done, total, speed, eta, pct = p.snapshot()
            self.dl_bar["value"] = pct
            pre = f"{p.label}: " if p.label else ""
            self.dl_info.configure(
                text=f"{pre}{pct:.1f}%  ·  {human(done)} / {human(total)}  ·  "
                     f"{human(speed)}/s ({speed * 8 / 1e6:.0f} Mbps)  ·  ETA {fmt_eta(eta)}")

        def on_close(self):
            self.close_scanner()
            if self.dl_stop:
                self.dl_stop.set()
            if self.share:
                try:
                    self.share.stop()
                except Exception:
                    pass
            self.root.destroy()
            os._exit(0)  # don't wait for worker threads stuck on slow sockets

    root = tk.Tk()
    app = App(root)
    if _test_hook:
        root.after(300, lambda: _test_hook(app))
    root.mainloop()
    return app


# ============================================================================
# Web interface (--web): a local web page that controls Shardrip.
# Works in any browser, including Chrome on Android (run Shardrip in Termux).
#
# Security: every API call needs a random key (sent as a custom header, which
# other websites can't add - blocks CSRF), the Host header must be this machine
# (blocks DNS-rebinding), and by default it only listens on 127.0.0.1.
# ============================================================================

def qr_svg(text):
    m = qr_encode(text)
    n, q = len(m), 4
    path = "".join(f"M{x + q},{y + q}h1v1h-1z" for y in range(n) for x in range(n) if m[y][x])
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n + 2 * q} {n + 2 * q}" '
            f'shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/>'
            f'<path d="{path}" fill="#000"/></svg>')


class WebTab:
    def __init__(self):
        self.running = False
        self.log = []
        self.status = ""
        self.progress = None
        self.result = None


class WebState:
    def __init__(self):
        self.lock = threading.Lock()
        self.tabs = {"dl": WebTab(), "send": WebTab()}
        self.question = None
        self._qid = 0
        self._waiters = {}
        self.dl_stop = None
        self.send_stop = None
        self.share = None
        self.share_info = None

    def ask(self, tab, kind, text, stop):
        """Show a question in the browser and wait for the answer (or Stop)."""
        ev, box = threading.Event(), {}
        with self.lock:
            self._qid += 1
            qid = self._qid
            self.question = {"id": qid, "tab": tab, "kind": kind, "text": text}
            self._waiters[qid] = (ev, box)
        try:
            while not ev.wait(0.5):
                if stop is not None and stop.is_set():
                    return None
            return box.get("value")
        finally:
            with self.lock:
                self._waiters.pop(qid, None)
                if self.question and self.question["id"] == qid:
                    self.question = None

    def answer(self, qid, value):
        with self.lock:
            w = self._waiters.get(qid)
        if w:
            w[1]["value"] = value
            w[0].set()
            return True
        return False


class WebUI:
    def __init__(self, state, tab, stop):
        self.s, self.tab, self.stop = state, tab, stop

    def log(self, msg):
        t = self.s.tabs[self.tab]
        with self.s.lock:
            t.log.extend(str(msg).splitlines() or [""])
            del t.log[:-400]

    def status(self, msg):
        self.s.tabs[self.tab].status = msg

    def status_end(self):
        self.s.tabs[self.tab].status = ""

    def confirm(self, question):
        return bool(self.s.ask(self.tab, "confirm", question, self.stop))

    def ask_password(self):
        return self.s.ask(self.tab, "password", "This file is password-locked. Enter the password:", self.stop)

    def start_progress(self, total, already=0, label=""):
        p = Progress(total, already, label)
        self.s.tabs[self.tab].progress = p
        return p


def _progress_json(p):
    if not p:
        return None
    done, total, speed, eta, pct = p.snapshot()
    return {"pct": round(pct, 1), "done": human(done), "total": human(total), "speed": human(speed),
            "mbps": round(speed * 8 / 1e6), "eta": fmt_eta(eta), "label": p.label}


def _list_dir(path):
    path = os.path.expanduser(path or "~")
    if IS_WIN and path in ("", "\\", "/"):
        drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        return {"path": "", "parent": None, "dirs": [{"name": d, "path": d} for d in drives], "files": []}
    path = os.path.abspath(path)
    dirs, files = [], []
    with os.scandir(path) as it:
        for e in it:
            if e.name.startswith("."):
                continue
            try:
                if e.is_dir():
                    dirs.append({"name": e.name, "path": e.path})
                elif e.is_file():
                    files.append({"name": e.name, "path": e.path, "size": human(e.stat().st_size)})
            except OSError:
                pass
    dirs.sort(key=lambda d: d["name"].lower())
    files.sort(key=lambda f: f["name"].lower())
    parent = os.path.dirname(path.rstrip("\\/")) if path.rstrip("\\/") else None
    if IS_WIN and len(path.rstrip("\\/")) <= 2:  # "C:" -> drive list
        parent = ""
    elif parent == path:
        parent = None
    return {"path": path, "parent": parent, "dirs": dirs, "files": files}


def make_web_handler(state, key, allowed_hosts):
    class WebHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "shardrip-web"
        sys_version = ""

        def log_message(self, *args):
            pass

        def send_body(self, code, body, ctype):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "img-src data: blob:; media-src mediastream: blob:; connect-src 'self'; "
                             "base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(data)

        def json(self, obj, code=200):
            self.send_body(code, json.dumps(obj), "application/json")

        def host_ok(self):
            host = (self.headers.get("Host") or "").strip().lower()
            if host.startswith("["):
                host = host.split("]")[0] + "]"
            else:
                host = host.split(":")[0]
            return host in allowed_hosts

        def key_ok(self, given):
            return isinstance(given, str) and secrets.compare_digest(given, key)

        def do_GET(self):
            if not self.host_ok():
                return self.send_body(403, "Forbidden host", "text/plain")
            u = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(u.query)
            if u.path == "/":
                if not self.key_ok((qs.get("key") or [""])[0]):
                    return self.send_body(403, "<h3>Shardrip</h3><p>Open the full link printed in the "
                                               "terminal (it contains a private key).</p>", "text/html; charset=utf-8")
                page = WEB_PAGE.replace("__VERSION__", VERSION).replace("/*__JSQR__*/", jsqr_source())
                return self.send_body(200, page, "text/html; charset=utf-8")
            if not u.path.startswith("/api/") or not self.key_ok(self.headers.get("X-Shardrip-Key")):
                return self.json({"error": "forbidden"}, 403)
            try:
                if u.path == "/api/status":
                    return self.json(self.status())
                if u.path == "/api/defaults":
                    return self.json({"folder": default_download_dir(), "home": os.path.expanduser("~"),
                                      "android": IS_ANDROID, "windows": IS_WIN, "app": IS_APP})
                if u.path == "/api/ls":
                    return self.json(_list_dir((qs.get("path") or [""])[0]))
            except Exception as e:
                return self.json({"error": str(e)}, 400)
            return self.json({"error": "not found"}, 404)

        def do_POST(self):
            if not self.host_ok() or not self.key_ok(self.headers.get("X-Shardrip-Key")):
                return self.json({"error": "forbidden"}, 403)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n <= 1_000_000 else {}
            except ValueError:
                return self.json({"error": "bad json"}, 400)
            path = urllib.parse.urlparse(self.path).path
            try:
                if path == "/api/download":
                    return self.json(self.start_download(body))
                if path == "/api/download/stop":
                    if state.dl_stop:
                        state.dl_stop.set()
                    return self.json({"ok": True})
                if path == "/api/send":
                    return self.json(self.start_send(body))
                if path == "/api/send/stop":
                    self.stop_send()
                    return self.json({"ok": True})
                if path == "/api/answer":
                    return self.json({"ok": state.answer(int(body.get("id", 0)), body.get("value"))})
            except ValueError as e:
                return self.json({"error": str(e)}, 400)
            return self.json({"error": "not found"}, 404)

        # ----- actions -----
        def start_download(self, b):
            tab = state.tabs["dl"]
            if tab.running:
                raise ValueError("A download is already running")
            url = str(b.get("url", "")).strip().strip('"')
            if not url.lower().startswith(("http://", "https://")):
                raise ValueError("Paste a direct http(s) download link")
            urls = [url] + [m for m in str(b.get("mirrors", "")).split() if m]
            folder = os.path.expanduser(str(b.get("folder") or default_download_dir()).strip())
            name = str(b.get("name") or "").strip() or url_filename(url)
            if os.sep in name or (os.altsep and os.altsep in name):
                raise ValueError("File name can't contain folder separators")
            sha = (str(b.get("sha256") or "").strip() or None)
            if sha and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
                raise ValueError("That SHA256 doesn't look right (64 hex characters)")
            try:
                conns = max(1, min(32, int(b.get("connections") or 16)))
            except (TypeError, ValueError):
                conns = 16
            pw = b.get("password") or None
            via = str(b.get("via") or "auto")
            state.dl_stop = stop = threading.Event()
            tab.running, tab.result, tab.progress, tab.status = True, None, None, "Starting…"
            ui = WebUI(state, "dl", stop)

            def work():
                try:
                    tab.result = download(urls, os.path.join(folder, name), ui, conns, 16, sha, pw, False, stop,
                                          via=via)
                except Exception as e:
                    ui.log(f"❌ Error: {e}")
                finally:
                    tab.running = False
                    tab.status = (f"✅ Done: {tab.result}" if tab.result else "Stopped / not completed - see log.")

            threading.Thread(target=work, daemon=True).start()
            return {"ok": True}

        def start_send(self, b):
            tab = state.tabs["send"]
            if tab.running or state.share:
                raise ValueError("Already sharing - stop it first")
            path = os.path.expanduser(str(b.get("path", "")).strip().strip('"'))
            if not os.path.isfile(path):
                raise ValueError("Pick a file to send")
            try:
                port = int(b.get("port") or 8080)
            except (TypeError, ValueError):
                port = 8080
            pw = (str(b.get("password") or "").strip() or None) if b.get("lock") else None
            if b.get("lock") and not pw:
                raise ValueError("Enter or generate a password for the lock")
            state.send_stop = stop = threading.Event()
            tab.running, tab.result, tab.status, state.share_info = True, None, "Starting…", None
            ui = WebUI(state, "send", stop)
            share = Share(path, ui, port, bool(b.get("public", True)), pw)

            def work():
                try:
                    share.start(stop)
                    if stop.is_set():
                        share.stop()
                        return
                    state.share = share
                    state.share_info = {
                        "links": [{"label": l, "url": u} for l, u in share.links],
                        "receiver_cmd": share.receiver_cmd, "password": share.password,
                        "sha256": share.sha256, "qr": qr_svg(share.main_link),
                        "qrs": [{"key": k, "label": t, "caption": c, "svg": qr_svg(u)}
                                for k, t, c, u in share.qr_links],
                    }
                    ui.log("Sharing is live ✅")
                except Exception as e:
                    share.stop()
                    if not isinstance(e, Stopped):
                        ui.log(f"❌ Error: {e}")
                    tab.running = False
                    tab.status = "Not sharing - see log."

            threading.Thread(target=work, daemon=True).start()
            return {"ok": True}

        def stop_send(self):
            if state.send_stop:
                state.send_stop.set()
            share, state.share = state.share, None
            tab = state.tabs["send"]
            if share:
                threading.Thread(target=share.stop, daemon=True).start()
                WebUI(state, "send", None).log("Sharing stopped.")
            state.share_info = None
            tab.running = False
            tab.status = "Stopped. The link no longer works."

        def status(self):
            out = {"question": state.question}
            for name, t in state.tabs.items():
                with state.lock:
                    log = list(t.log)
                out[name] = {"running": t.running, "status": t.status, "log": log,
                             "progress": _progress_json(t.progress) if name == "dl" else None,
                             "result": t.result}
            if state.share:
                sent, speed, active = state.share.stats.sample()
                out["send"]["stats"] = {"sent": human(sent), "speed": human(speed),
                                        "mbps": round(speed * 8 / 1e6), "active": active}
            out["send"]["share"] = state.share_info
            return out

    return WebHandler


def open_browser(url):
    if IS_ANDROID and shutil.which("termux-open-url"):
        subprocess.Popen(["termux-open-url", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


def start_web_server(port=7777, lan=False, tries=1):
    """Start the web interface in the background. Returns (server, state, local_url, lan_url)."""
    key = secrets.token_urlsafe(16)
    allowed = {"localhost", "127.0.0.1", "[::1]"}
    ip = lan_ip()
    if lan:
        allowed.add(ip)
    state = WebState()
    server, err = None, None
    for p in range(port, port + max(1, tries)):
        try:
            server = QuietServer(("0.0.0.0" if lan else "127.0.0.1", p), make_web_handler(state, key, allowed))
            port = p
            break
        except OSError as e:
            err = e
    if server is None:
        raise OSError(f"Port {port} is in use ({err}). Try --web-port 7778")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    local = f"http://127.0.0.1:{port}/?key={key}"
    return server, state, local, (f"http://{ip}:{port}/?key={key}" if lan else None)


def _shutdown_web(server, state):
    if state.share:
        try:
            state.share.stop()
        except Exception:
            pass
    if state.dl_stop:
        state.dl_stop.set()
    server.shutdown()


def web_main(port=7777, lan=False, open_it=True):
    server, state, local, lan_link = start_web_server(port, lan)
    print("=" * 64)
    print(f"  ⚡ SHARDRIP {VERSION} - web interface is running")
    print("=" * 64)
    print(f"  Open this in your browser:\n    {local}")
    if lan_link:
        print(f"\n  From another device on your Wi-Fi:\n    {lan_link}\n")
        try:
            print(qr_terminal(qr_encode(lan_link)))
        except Exception:
            pass
        print("  ⚠️  Anyone with this link on your network can control Shardrip. Don't share it.")
    print("\n  Keep this window open while you use it. Ctrl+C to quit.")
    print("=" * 64)
    if open_it:
        open_browser(local)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        _shutdown_web(server, state)
    os._exit(0)


# ============================================================================
# App mode (--app / Shardrip.exe): the full web interface in its own app window.
# Uses Edge (built into Windows 10/11) or Chrome in "--app" mode: a plain window
# with no tabs or address bar. Closing it quits Shardrip. If neither is found,
# it falls back to your normal browser plus a small "Shardrip is running" window.
# ============================================================================

def find_app_browser():
    """Path to a Chromium-based browser that supports --app windows, or None."""
    override = os.environ.get("SHARDRIP_BROWSER")
    if override and os.path.isfile(override):
        return override
    cands = []
    if IS_WIN:
        for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"),
                     os.environ.get("LOCALAPPDATA")):
            if base:
                cands += [os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                          os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                          os.path.join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe")]
    elif platform.system() == "Darwin":
        cands += ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    for c in cands:
        if os.path.isfile(c):
            return c
    for name in ("msedge", "microsoft-edge", "google-chrome", "chromium", "chromium-browser", "brave-browser"):
        w = shutil.which(name)
        if w:
            return w
    return None


def _app_profile_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "share")
    d = os.path.join(base, "Shardrip", "app-window")
    os.makedirs(d, exist_ok=True)
    return d


def _running_window(local_url, on_quit):
    """Fallback when no app-capable browser exists: a small window to reopen or quit."""
    import tkinter as tk
    from tkinter import ttk
    root = tk.Tk()
    root.title("Shardrip")
    root.resizable(False, False)
    f = ttk.Frame(root, padding=18)
    f.pack()
    ttk.Label(f, text="⚡ Shardrip is running", font=("Segoe UI", 13, "bold")).pack(anchor="w")
    ttk.Label(f, text="It opened in your web browser.\nKeep this window open while you use it.",
              justify="left").pack(anchor="w", pady=(6, 12))
    row = ttk.Frame(f)
    row.pack(fill="x")
    ttk.Button(row, text="Open Shardrip", command=lambda: open_browser(local_url)).pack(side="left")
    ttk.Button(row, text="Quit", command=lambda: (root.destroy(), on_quit())).pack(side="left", padx=8)
    root.protocol("WM_DELETE_WINDOW", lambda: (root.destroy(), on_quit()))
    root.mainloop()


def app_main():
    server, state, local, _ = start_web_server(7777, lan=False, tries=30)

    def quit_all():
        _shutdown_web(server, state)
        os._exit(0)

    exe = find_app_browser()
    if exe:
        t0 = time.time()
        try:
            proc = subprocess.Popen(
                [exe, f"--app={local}", f"--user-data-dir={_app_profile_dir()}", "--no-first-run",
                 "--no-default-browser-check", "--window-size=700,1000"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)
            proc.wait()  # returns when the Shardrip window is closed
        except OSError:
            proc = None
        if proc is not None and time.time() - t0 > 4:
            quit_all()
        # The browser handed off to an already-open instance (or failed): keep running
        # with a small control window so Shardrip doesn't vanish under the user.
    else:
        open_browser(local)
    try:
        _running_window(local, quit_all)
    except Exception:
        print(f"Shardrip is running at {local}\nPress Ctrl+C to quit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    quit_all()


# jsQR 1.4.0 (https://github.com/cozmo/jsQR, Apache-2.0, see THIRD-PARTY-NOTICES.md):
# the unmodified dist/jsQR.js, zlib-compressed + base64. Used by the web page's QR scanner.
JSQR_SHA256 = "3325b0888fa4745c4e6940897d8c4f426fbaae76901fcbfe1871a04e90a51655"
JSQR_B64 = """
eNrcvX13Hcdx7vu39Sm2uO6JgYiE97zPkJJz5zVHJ7bsIznJPYdL4cIbJVgkwAuAEpmE3/12Tz09+zd7zwYgys7yPV4JRBR6+qW6
uruequrqg5dvL09vL64uVz+dn7w5Pv3hny8vfjy/vjl+9furs7evzrvzlxeXF77AwfXV1e3j1cvj09ur6/eHq//45FcXLw9u3785
v3q5On/35ur69mb1xRdfrH59dfLn89PbX6/+7u9W+vPrsa7ZXw8/+dWvjHw0fRwqPzh89smvzl/dnK82LZz5jqiK0OexCfvD0fHr
M1+l/Xbw/NtNT3frWuqt/1j054/+fPM/v3707UKHXCHPhuUSHw5DAzfnr16uPvW1v720Hp39evUPRn66uv3+4sZ1T4M48Ky8Pr99
e325+s3fj//7zepg+qvx6MYVWv3mN2GSGteHm9vr4zefTF/8yv31T9+fB1afHp9+f46//nh8vbq4vLk9fvXq/Mym1jP8Pz48mwrt
1nV9/v++vbg+n7qKEpPYvHihPr1Q6Rcv1Ocvz/zIFmr31bffn5/+4KYk9PfixnVvp9dewrZ7/TzU/i2rd2V/JSbu/yBI2jN+9mG7
Z9fnx7fnq+PV5flPoXcHx5dnqzdvb1cX7v8ub6/cFIrFh/zaMzmI+h3d8Hyfdfzi6Sr88fHsD6+eOvlyYjenahRP3ezNBvJsH7P7
d+enb92YbjfysTClWo7k16kbwMF8lT5WDeG/G/qCJBzu7dLw6vg79uf4ZvXq6vjs/Gy3Q0evHMNur9+e763sa5t4X11Y2m4Rbmpn
cQnJvPMUiA+7rcxXhv/mhsx0rY17yOpgwwL9xbEAHy9w6Oi1G5wKP3togzvrZKni0wUZ3NeCNtfvzm9vz68n2Vi9vLpefX98/frq
8n1g7D2NnvkdMWxdk2RcHr928mK1by1at8A/Xaroav714fZa/8PI8SPr+B+vr96cX9++325x/smvTq8uX1589/b6+OTV+eLC+tX5
5dvX5/q7l7itP7sRPNUwZn/4cLh3R9m7v7pq3Nl6/PbVbT92es7106vXb45vL04uXl3cvl/9dHH7/ery6vJJmAwJzD2TccnJsE+2
2Og3LE16kEJ/pGpxvHhxfmOCs/qH2Xinrm4G4U+x1WxtPf/1mf3p198+W31YPd1bgzVhXLjZrcd9POPuotgd2Cger359/OtJ0p4t
rHv707OHzJBE7M311e2VP9ePvj+++cNPl0HYxs3xnhm44gzYJvF49UYVYKQPaWr3+xln5n3fdObN25NXF6cvnDR9/+LFPd1947r7
6NG+On/n9ufV+eXt9ftp03anokawuz3oD0v6wVLbXhtJOGUfpp3zl/8PIzl47v69Wq9E21W1Hq/uPNHcAvrk0Vu3HTv96+L01nHr
k3v2okebdfTI7UmrH49fvdX+svI7h1+EzcXt749dhe8cF1y3Vv/36avjm5sVu7caFcWV+99Emb46ODu+PX7s9omz2+9DKf8/r2ke
jVRX7/jfZ/O/fX9+8d33t+6PvoKjV+eX37miv1ks6kuooP3lw/hz6sPR6ag49a/fuB1rI/arg7Gyxytrir2ThHg9azMS/9s/Ox2r
bF8dv35zflZfXx+/tzpWfx8qCUNVR55t9WSzjtxyn/Xl3ePVe3bBKaAH71afO3n4z/9cvVv99guyzJHeh7+9n/62Ow6MZTxUNoz7
sD3WTz+dePn8vRsPWvts9e7be8dzszCex6sfd+Z8XwPu4x8dEIkcClk/pLGvz7/z7bDJV+cv3SZ0e/VGkxBmdqsb/hQ78KLthcGV
fjby0v3D9cM+cJTPPtvm4/SZXwm+qWcrPz/+X+5Dk8vVu93vppG7Tosrn3764+GzWaEPWxOjsWtuJhY4JHdw6D7VCj7i4kShT7SB
fDj0aoLj6d/WlvKP55fnrrp/HP549er9i8j1fWkrjl3paW6Pz87+cP3N2xOHLE9v/3E4cFvKSWC0mHS8+rfVyTMPRW9vXrll+vTs
4sbrS0/cL+dPL6+enFzc/nThgPKHiX1btbqObFG2+vuztsDpq4M31xevnaHiR8ftm4t/H/XNy+b45nxnbUwFXUPTv7c2O1+D+7P/
z9ZfvvMNHjvI7+t2RdTKVik39j95trgCfkOzTWyq+XCr9Kur7x5WOiyM6NnuOrtw9PUz95/PN0Nwv+4ulVkHn1/4PeHdfJ34Jt65
zSOek22zDPvg2LWFVeg/dsX+bYvZh6u/W23GtHqyig4fIkZ3Ld97h+9b2c+CwPXn2wzxHLlY2sTHgv9+fn2lidpaYkdSeA/MwLNz
ih29vL56ffB8/e3htgBcXZ7/oiqjqUrr7FQLdvPXrpqLN6/mZzNXeJji49EuNp56J/bPPYfd+o6Dbs7TgznDj791e/mcdOKsOf9t
W0Dm5+HSoC4uvbHyfD6mPQPaFYLrq59GpvfX11fXB4/a48tfe/uOq/J2tX50+ODhsdc7I3UDuX8cJ28vXjmQfnn1+uL41Ww0Z+ff
XZ+73ez06vzly4vTC6eAb4/PinhN5d4hfnnpjoqLM6fAqyl968DkjSt9fLlv3L4ddOFOuZiWyVJFfq2iohvJ/a7Kp5595jeK6Wt+
6RaS+xiUZ0ua5d0LivUd3jtLblr/kpJ2e/yD4/zVdwfrw/uFDSJ1bz+dYO7v56IEb1WqMlPd2xqRmOgaQZEtfSj+W9WH9upC0ZLm
9HHaiP/y4OXF+auzLRnbEhj+LcCvh4nQV1ezio+WJWic5bEfXiD8f5/tXYm/U/OrhU4929trffVbp/86y9HO+lwai7clnB+fXVw6
C/D59evV67c3t6uT89HCNZ6u/lA/vnzvOu+KnL87PX9zaxb3K2/PdLvPG8debWCP1o9mlftRvby4vrn96uryf9tRHc3VmJ++v/Am
/Vmhz5c4sT0efrFnaKM0oNhnn+1DIIGX875+8cVCR/Zina19dJzfceOd/eWuHoyOsYfVvrxLL7DtyYwDWxDsTp1tSfCW1Le93TRt
du+kucPk4tvd/ny4V8tcYNMSi5a5/mFJMfMbBHZsHXbctPft2UtbxpMg49uHwlYzFzdaEj+vmWklP6gRZ3NpqSnsKDMPavKusbr/
t5q+fVCHZnBz1p8rt6tcszteKl8cz3e7sSfGuYPDPSrPWNE+vWn84301+Fb26Us3r70T57qdS9sOh+Zb+6vj6+92vrGuLH/ku7rQ
UuD7bxdq1N+2h/TCGwqf7xZ/vDSSbx/vGd+LYyd3j5fH4f4WfbuXXW9fdxcvX+7ds/aPY4uDI1FV7f3ICeN+rt2N0zcNLG5zGodt
arvtP79Y5MCsoVkLvsV9o7i/A9Cftk06S2Lz/MIxZtP84kS6iu/Se3fU94ONOvM4dO7wQVvAIvi9cW6V4+ttlcyo9wOczWm7b92j
puhjVr3ZoPaejLPCbqhnb8fdbVnmtwxJS9K412Ckuk0MMPbA1IOlc9hNkLH3oydYzf68CZbKfscWv7Ole0PHg7foe6bds/T45+3T
x5PefdzeN8snP2M7H8tPdZ+0v1SCQj8/m2p9MoPmSyKlbxalasOq7aE/31bSpqr/bFX/2VV9Eqr+87J+OAmt6/Cf79u/5oUfLwq5
dfHxnJPP/zwz5u3TH/968t68/y+0Gv3VjEX3L6q/+GboZlra6H/trsgZ+a/ZGs+9NcR5Zuvb/UYhP+jr8xuz6ayfPcSo5VD8//DA
/XoTfPXu39Yc397pniMEZ/76xbO+6We0r5++g05nCJFhrO5uYHfkxKJ3AVcw/OxZVpux3mxZxxb2HCu0TyBGXmz9Lhbah8uyo3aX
ENweMY/uEfMHjWVxv3ysbw8fLwL1u6SfQ9xjkvRC/gCzpBXbMk0mf2OmyZOLy+NrNwHXe02TqUqenZ9end1RLlO583fj1FztLxkF
a+erq9PjOwvOXMROqXOsGj3gQVKmStzfvVIyVXg0/us8FLd59Cv106n4UjjI21ev6MuapPXFuCs/3rQ1dnn67Zkv8Dn/OkGbF1ty
zR7PK3kRPX9B7QO8PPcmVPD1SP/W8B6jxi0caZPmP5+m78j+dTDVfTRj0uaMHr/cc3TubjyjIL3vXPDH09Dq0cn72/ObxztFz2aF
bl1Hdsucfv/28oebTSn7fbec98G5gW8KirBbMvDo6T6L3tWbr31sSHt17Rbw0xX58+aNMwcPYbluuH10dvH6/HJsz51Sj/fV+zsX
QnJ/tev9dZxc3d5evf5F3Vui3tnagzv9M2oOPB4u3N2E6z8e+4BINyGoIZS4k5d3fu4L3Deu/RVsytw7E/Wri+8u3Xhvl+o53vrj
bm0f5qQPy1bb2c70QRvxeNT84U3Y9UyezR/tSLVr0EXCucXz6Nj+2Tiw9ujxJx+wmfpLJAzd24RSOe3txwu3klR/2AD8nrD1p1Hp
+fHKaedeQ1vt/NVf8dAwfL+vJvp8BDZwnWU/nL+/OQglHTr+jw+HC0qQK8CNSeWfu/9+O0bWzDpiZI+08bu2eW16o8L3/dXbV2df
mgv+i1D4aIet46hnnEXd+4qbZ3/wDoFHmyZdPKu1d342/un+Zq8uX+mTj291NJHi3D8K/16WB/LF6VOh8NloCp2+dcjgQkOxP4Tf
Nu1O6tx4kO+M/R82FTzdtMKjWxU439jBX292Dud6wT1d3nDj6dT9WTjMllb54RO/8KAt+l+XtEijbymP6d9q6PBeDW6tkl/3//jl
H7568c2X/7t3JUsj/v7Lr150/+ur+vdfti++rr/6R/+nOMUm5a5ENOe3P52fXx6MzbuLPxfuKHt9/G4rNHD8q9PA3J/dpPifT0X7
rS/tae6naH4WvB/4woVAbOIrT9wVq+NT7++9WR1fuxgwF2s+wnf76MZ6/PMDpRVbvDcS+d44aQU/Pyg4mZL3swOSCZMfFCX80BBh
z7+fFSZss7SLwOYxslM7d+9f9m1YuDzOGHjub0zOmen+kc57vWWa+v3xK3cyvXZrf5yiN04Y3L/dDb1pb50iI2xG/A2/KztfLl4f
f3fuyzoz0HtvrT6ftsmJ8seLd875q6lfFKNnn+zELa8taHk5WnkWGL22sOg7AqLHTVtx988PDvxkTfN0aOz5bLXeMpiOQ7jvo2jh
o5P7Poq3PtpiFMKv10dxFOfuu2vfwaMiylxEkOuV/2VdxP6Xk8Nlfcv35PsrN3tXl+76msWgt1dvR2eym4Pvj07PL15p2f2G2xo0
CT/DF6f7v5Z87fv85JXbQ/94dbGJfdDkL/br8VJz25IxL2KTv0X7fKme7VJ7xMl17HbWM2thl/z5Mm8Xii5LozeizYyE4Q9+y/9i
9eXleGP8/cLfj9/tfri0HDAli2ti34Kbffduf9zIaCP28vq7t6+vbi7G+yrbguw26oNd3v397BB1C2N75ndKvF8IgJFvdfXZF/Nu
LJc0to6S6/55MJ6+s8/2tGDstu+O3zkzxbv7v/twR6zQ6LBxo/Wb5hdj/92hO1b/5uqnA4z68Sredor4nd7358k4ms+/2FU7lubK
7dVfvvTtXhxbioILHxI2mm9PHMz7wd8af3X102N3e9h153w8xTztWH8e7016bX31alzsTmT8b0vtnB1f/2DcuTlyIuzdG7fumq1T
1n46X51dudi029VPPvTMHRdvdRlXzPDN+4vhP3kVfXV24WHP2JWldlx3fRibQ/JOdT12N6bsPvm43Yz36Vx0mrupbT1x+qQ7zi5v
nXfHjWG8X+Uj4saT7sqpSs6UfXnlouSPFlpaalx3NcVA1+Ibv8GNS8mRbsTVm/H4PHc3f1/pErXj+ZOVM946VdVF8ruuWCfd3177
fuw0tZES/+lvtu8RBIHYWjm/dTHnDlbsLrrfLsfZTaf59bW/fO17+sg6duKG9t2129TOHplovJku1oYR+un93vXTbe1ONE6urm9W
J+/t2u214/G+xnwjNjerC9PSJGrKCfDm+vzHi6u3N366jl+dvn117KGUze7IbCddf5KUnhx7VcVdwb+jLZ9dwjo7CujJ8bU3sK1u
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
rfiXg3+t+JeDf634B5wXt+IfcF7c5tPTYxua+JeDf634B30jbsU/6FdxK/7l4F8r/kF/iVvxLwf/WvEPuk/cin8F+NeKfwX414l/
BfjXiX8F+NeJfwX414l/BfjXiX8F+NeJfwX414l/BfjXiX8F+NeJfwX414l/BfjXiX8F+NeJfwX414l/BfjXiX8F+NeJfyX414l/
JfjXi3/AKXEv/gGnxL34V4J/vfhXgn+9+Ad8FPfiH/BR3It/JfjXi38l+NeLfyX414t/JfjXi38l+NeLfyX414t/JfjXi38l+NeL
f8CXcS/+AV/Gg/gHbBoP4h8wZxLs2cDYSbBnw0aRBHt2zW/F5zoFTXwG3kqCPbvOQROfYXtIUvEZNuQkFZ/rCjTxua5BE5/rBjTx
GZgzScXnugNNfK570MTnegBNfIbNKMnEP9jSkkz8g+0hCfZs2CiSYM+GbT0J9uwG/Av2bOCjJNizG/AvE/8a8C/YsxvwL9izG/Av
2LMb8C/Ys2EbSTLxDzaUJBP/GvAvE/8a8C8T/1rwL9izW/AvF/9a8C8X/1rwLxf/WvAvF/9a8C8X/2BbSnLxDzaoJBf/WvAvF/9a
8C8X/1rwLxf/YA9Lgj27Bf+CPbsF/3LxDzayJBf/YEtLcvGvA/8K8a8D/4I9G3aVJNizO/Av2LNha0mCPbsD/4I9uwP/gj0b9uIk
2LM78C/YszvwL9izO/Av2LM78K8Q/zrwrxD/4LNJCvGvA/8K8a8D/0rxqgf/SvGqB/9K8aoH/0rxCn6rpBSvevCvFK9gB05K8aoH
/0rxqgf/SvGqB/9K8aoH/0rxqgf/SvGqB/9K8aoH/0rxqgf/SvGqB/9KyRrsL0kl/g3gXyX+DeBfFXx34F8VfHfgXyX+DeBfFXyf
4F8l/g3gn2EmF3SCdg0zORraNczkaGjXMJOjoV3DTI6Gdg0zORraNczkaJg3w0yOhnkzzORomDfDTI6GeTPM5GiYN8NMjoZ5M8zk
aJg3w0yOhnkzzORomDfDTC4cB/NWi3889xvxj2d8I/7xjG/EP57xjfjHM74R/3jGN+Ifz/hG/OMZ36h/PFdb9Y/naqv+8Vxt1T+e
q636x3O1Vf94rrbqH8/VVv3judpqfnmutppfnqut5pfnqmzhCc/VVvPLc7XV/PJcbTW/PFdbzS/P1Vb847naiX88Qzvxj2doJ/7x
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
Do1bPCrVD/xXa+19i8SzUTz1YltYB9N18Grjcdh23pL2skf2A3u/aIRXK83fR3i1FUNEeLWanQax4zymnogH1Pte9oJ1zgu8mqUV
vNoG52Vb35cG+K9OLkMT/Yc5YNrOKlH5mzibVPuaI+ctLR4rb+ctub3a/FflexM5b8lrd5Hzlib3q+wH3rn8sR+40bxAZD9wdh86
c16Q9q9F/Fd9XnOcGatcy9/W//rdRuIZOn8T38P3rvotwfkjnpfmfCP+q4PHKqyveg08sr5au2wQf3WnueEIr6ZR6bK+OnusB6/u
5HsYOR+40v7syPrqUjvdTNwbP69nLVrlhf3A9veLC/up1UYkeLVVW5c4b8lr1gn/1UZrHYn9wI7ZlFZezcO1NPCpmfy8LSZhlm2L
Z+PnEc9m9vPWMhQbX8ceEa37pXbzH6xkY4+N9jqnljmPne9lfVDlIMGrWW1nwn81iyES/quTxnqp47wgjZsSvGqfn0Q8m3pxGsyZ
a04hEc/G8RxSxx4ljeVTx5y5ylqCV33Geeo2nySnwZyl9lEkzgf2vGNiP/AuOQ1iOvobbbyq+YPE+upOY9EUWHPQvEBifbXXWDmF
LaaedGZ9dRSLJ9ZXK62TJPxXd5Ofx5qXxmaJ9dVJ86IpMAZRO54CYxD1ZYl4NmPl543EcZJW+K92o/Mys3/Sz6P8iS8T66uzvzm8
6pgbKRKPSutvCR+7RfsZUg+TOM89Pv2at0hbjEj1oYmYG7PmZFLP/mL1UaknRlrjdPHH1rxF2vYsun3p2XPX+Xl8D52xkHq+R/K9
+PQnvwf7Lfw9iLkxJ7/bzN4oP2/TT2UXH7tZPhdpQL9sG/ppHJGGbb+FtB/QT/7niTH1PPg69NN+lTSgn8beaduz6Lq/jalHvwf6
uR4N6Df6eYyp3WYP6Kd9+mlg/mpyutuYRuluexa1LpRG9BOLp3VMXfb0qg6O2/ypvts6pi5jJGk1wiTa25hG9tx1zkvE5nQT51na
tu35lC4je441r5dG9twlvxs+xm43Rub/ovPHnrHg98WfXb6baWJMqLmbNDEmdJ88oZ84Kk3ol21j/llj/jShn/Yxpm3Por/bhH4u
axP6TX4e+mmNKk3o5/b5as+ivu+EfpM12OKpO3/opzM+0gSTaH9xmrf+SPmbiQ+mteO0nWHq9m87w1RrJ4kx9W5nG/ppTJ1m9NN4
N3GG6U68mlgD2mlOJrEG5Ni8aUY/7Y9IM/p5LDVv59c5DfYs7pyXbc+s2hfWgHauC4ypvTc0Mabeue9ZtjNg9d3Ys7iT72tiz+LO
dXrzsXMfwJ7Fnfa0JfYsOu5hWtAvOV30y06j5zrnmTkFjzE5E8Z+mpkzYXYa82fOhNlp3JlZA9qpzc6MqXejn4cGGjdl1oC8ZzGz
BrRTGc+sAe3UxmbWgBxPLrdoMPt5aLD4PdBgcRqci7PzdcyraHyaOROm2vnd8POXf0/Gx67SeCPjY1epDmZibtg/IG8xIlVn8naG
aePrOINTa0qZPYuVxiW529axB9lYh9VYJbNnsdJ+/ryNqbU+mLvtHHqngX6d3w39gu8lzq3muDM+dvazztueRY2LM2Nqz7ll1oAq
1YXMGpDX/TJrQEFtdt7OMNUYPbMGVCXnBf3U52XOMK3UR2X2LFZijYyPXaW9Qpk9i5X6qMyeRfuTZPYsVr2v287g9Luhn3x+MmfC
VNpvlokRWWk/V47bvIryTIxIn4WUiRFZuY1gz2KlMVzGx67SmdAZH7tKsSAyexar0dehn9sc9ixWk/OMfrPTHZln9fO2PYt+Hvq5
LdnOMNWe8swZppXbCM4wrdQfZc4wrcXdmT2LtdbuMnsWa9d9zjCtd34ePhLaB5XTtoahb8mexbr2vcwfaO4ws2fRsXlzYs+J9n7k
7UyY1vnjDMnW77HFw1WdWdeAyt5p5YU1oNrtAWtAtet0Rr/o69DP7QE+drX28GXOMK217ytn9NOaYd7WgJJt6JedLvpp3SBvPnZi
9oyPXa1xcc7bHLKvW3nLMZUzZ5guWqPKxNyotZcks2fR50FlYm7Ug6/b5kBVTtmzWIvF8xYjcvTz0G9yXtDPfXKPfu5re/TTHua8
nWHqurWtAbmu9tueJz8P/VzftjNM3VfAq7X7c84wbTTWy+xZbLT/JQ/bfgvbOA9A/JuJEdlo/iAP2xl+KmucCdO4j+dMmMb9OTEi
G81F5mE7k8PP40wOzT1k1oAa1+ntTJhr78H+dvfd25kwrXVhz5P2uOaNVzVPmIkR6bigmRiRPsc6s2ex8riOmBuN24MR/Vyn2bPY
uD/Hxy6L1fKIfmLJPKJfdJ7Rz/0+MTca97Uj+mmOIrMG1Livxceu6a0V+mmdLm9rQO4HiRHZaN4iEyPScUYza0Cj5mTyxBqu9hPm
Cf3EpvkqRqTag2mLMez8od81G/ppTSlvZ8K4/rIG5L0uedr2zKqcbjE3Gt/Lef8uk/Cqzx/K8KrP2c7wautxLLzaus+DV30OX4ZX
fQ5axseurZzGFnPDz4vM20pneLXVOmKGV9vke3vOe/W9+Bi7/4BXW5fdedtzLK3g1db9Ebzaui5sPnYeAy/bnnfpAq+2mvfO8Gqb
fS/6Jd+Lftqvl+HV1mNReLXVHqoMr7auR/Bq6z4PXnU8tAyvtqOfh37qV3t41b7/PbzaikN7eNWxJfptDWiYZUMD9bU9vNpOThcN
xKs9vNqqb+zh1U79Rw+vdpXzggbyf+vhVa9v9fBqO/s6ypDqar/F3JitwUL830P96OHVTnW1h1c7+XL33bZvWLrAq53qZQ+vOi5e
D6926nt6eLXTPEgPr/r8gx5edd/dw6td4/z13Ctd4FXve+jhVe9h7uHVVnvk+pVXy3XSFF7tNO/dw6ud6mUPr3Za1+jh1U5zpT28
2mVfh369beintbseXu20z6iHVzvxYA+v+jyAHl7tXI/g1U7zkz286n0tPbzaTdaAuHOqvz282k3OM/ppbrOHV7vJNmKUun7Aq53m
0Xt4NWj+pYdXO7FaD692rlvwatB+uB5e7TTG7OHV0Pp5q35B8389MSIr6wKvhsbvwTkTjfM8YVNdhVeDyz286liIPbwadIZpD68G
jTF7eDVojrGHV302aQ+ver9UD68G1xl41fGd+7SdN+zr0Co7fz33On9opb6ih1ftz97Dq2Fw/tBqcBprWQvuA+BVn8fYw6tBzNTD
qz7ztodXg/Z39vBqUB/Vw6tB6wY9vBomp4F+k9NAP3FZD6/an6SHV4PLKbwad84f+snHpIdXo+Yt+rydieDnLdj0bvCqfdx7eNXn
yfTwapQvXg+vOv5qD69G1194tdN4o4dX7TvXw6ux9r3EmGt8L/FxXI84E8b7O3t4NTZ+N84bdt8Ir0bNofTwahTj9PBqdHmBV6Pm
D3p4NWoPbo+Pnc/g7OHVqPnJHl6Nmnfs4VXvA+jhVcfh6OHV6PEQvBo1d9jDq3Hw89DP9QNejVpf7eHV6LYdXo3a19fDq9F1AV5N
2i/Vj+gn5uzh1ag5ih5eTS6n8GrSeTf9FiNSbNDDqz6Tt4dXk+bl++1MmODr8MdunS4xDjW+78ftTA7bthiRft7IeRnOH2cSRb8H
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
lnv1HpwJs/P4gDNhdmLYkTNMK48FBs7wc9s0oJ/bzoHy5zZx4Pyrnd+XM3TdDnGGadX6PVb9Ks13jpwJU2k+Z+RMmEp+CSMxIivX
c2JE2q9oJEakfZJGzjCtats4U0f7ZEbOMK209jmO6Od6PqJf63s5/8/9+cqrxeb3QL/O74t+bg9G9HPbOaKf25IJ/eTTMHImTCX/
1ZEzYRyLfSRGZKV5qXFCP7exE/p5nMh+4ErzYeOEftFpoJ/HBxP6uX2ZtvMTpRVnmFZi7JEzYXwG3Tihn9u6Cf089uEMU/tRjcTc
sJ/SSIzIShw/EiPS5x6NnGFayUdxJEak/YpGzoSpXKdn9BMfjVvMDc0/j8TccKzQkZgb1eB00W/0e2wxIp0X9NNcwTij3+w00M+8
xZkwldsr/FcrtzkL+rltWtDPYyRiRDpm8bign9aix2XTT9+DM2Fqt4mcCVNr/nncYm6YezjDtHYbxhmm9c7pEi+h8nuM2A46T8Tc
cIyviZgbtdrYqSXOqNaFppaY8rXvbTlrdycb56hr7Wlq0UB7UqcWDVqniwat00CDzjY0CH4eGnR+XzQIzh9nIOr8jYkzYWrtIZ04
E6YWu0ycCeOz26Zui9Oq/HVbnGXfi37ajzR16Kf2ZerQT+szU4d+yfeiX/Z16Ke1yokYkbX2iEwd+mkufNpibmh+YyLmhs9hnoi5
UY/O86pfey3PW5x06UyMyFpr5VNAv9E29FN7NXEmTK25mymgn+bWp4B+GidOnAnjGEvTdobpzumin/YTTpxhWmtsMXGGaVM7Xc7Q
3Tl/IzZrgH7aEzNxhqn9vKawxV1S2eVMmEbjkokYkfY/mlZeLeF09G4rr5brlO7Kq8F+QNPKq2VrrdMI2JwX9FN/NEXOgI1+3nYu
ospuRL/kvKCf6xbrq032dat+jca7E7zaaLwxwav2rZrg1UbrMxO86thOE7zaaA/aBK82LvfwaqO+Z4JXG5e1tJ2Xq7KRtvNy/Ty0
0l7xCV5tK1+3atU2vo4z53e+buJe54+6Wvs64rtoTnqCVzvt/5vg1VZrQBO82mpcPMGrPkt0glfb4Hs7bL4ucHa+87LqZ5+kCV7t
3EfBq638yid4tXW7C6/a92aCV1v5B0zwapv8buinOZ4JXm01lzvBq62/Obzaas1wglftQzTBq63bZ3jVfjYTvGpfnglebd1ewavt
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
pGJbNZga5yVhW2TL2JxGTxp+t1UDRQAsNjTofN3Evc7LzL3Oy1qGJs31NfDqpD65gVcntSUNvCrvv2JDv2wb+mk9r4FXJ80dNqyv
TslpoJ8YooFXp+x70U8c2sCrikZYbOjXO3/op/mcBl6VB1+xod/gvKCf2o0GXp3VjjfwqqIqFhv6aX6ogVcn1bcGXpWXYLGhX/a9
6CeeaeDVafK96Dc5f+h38OArNvTTvHwDr06L3xf9Fr8b+okXGnh11j6ABl6dXd/gVXncFVuFTc+DV2fNGTWsr86Nr2u5TlrBq7PW
/Rp4VVEaiy2SrtNY9ZtdL+HVOdjWkxc/b8AmDeDVuXFeJtKwBuincUSTtrKm/MGr8hIsNrQKvhetNGZtWF+d3ZbAq3OncgCvztoD
1MCrc+d00Sr6uk0rX4dWwdehleZtG3h11l6wBl6dNT5o4FV5nxYbZc1tycqraXEbAa8qEmSxoZ/mLRp4dXa7Bq/OmkNu4NVZDNHA
q7PGLw28OrvthFdn7XFo4NVZcx4NvDonvwf6uZ2EV+fs/K36KfJgsc3Y9I3g1cX9ILyqyIPFVmGTzvDq4v4IXl007mzgVUUjLLYO
m9MN2KQLvGp/lwZeXTRmbeDVJTjdHpvvJXqMyyS8urgewav2DWrgVfvoNPCqfY0aeHVx2YVXF5c1eFV+asWGfi5r8Ori8gKvyouq
2NBPjN3Aq/LaKjb0c38Jry7ut+DVRePdBl61L08Dr16rb/DqMlgX9HOft/Jq8pxCA68uGu828Kr9hRp4ddH8WgOv2jeogVftB9TA
q4v7Mnh1mZ0G+omnG3jVPl0NvLosvo6Tfdzvr7yadh7bchr5buf8TdhUz1deTTv3jSuvJvvoNCuvJkVfLLYKm/Ky8mrauf9debXY
/Lx2tXlsu/JqsSl/K68mRS0stohN77vyatp1eo+VV4vN6fbY/Dz0c92f0C/4eejnuj+hn8fZE/p5/Dyjn+a+mhn9tOekmdHP/eCM
fu6PZvRz3zOjn/xYmhn93JbM6JdUnmf0cx8wo5/7mRn9XPdn9OudvzXSZ+V+a0Y/+co0M/pNThf9ND/ULOinOelmQT+PTxf003x7
s6Cf5q6bBf2056RZeTXZP6pZ0E9s2izop72wzcqrqdJ+i2bl1bLc7ef12KTpyqvF5jTW8leJG9uVV7P3CrWc7lapLrQrryZFDyy2
VQNFoSu2FlslG2VIa/ntyqtJ0e+KbdWgCk4DDTR307ZoEJw/NNB8cduiQXL+0ED9W7vyalK0umKbse1kW7Ad6mDL6W6V9nm0Hfpp
/ajt0E/zQ22Hfurf2m7Tb5GNMpR9Hfppnant0G9wXtBvcF7QT+v2bYd+6vPaDv3EnG2HfqPTQL/RuqCfmLjt0E9rs21AP60ztQH9
tE+hDeg3+V70E1+2Af1G29BPdbUN6Cc/yDagn/bGtwH9tE7cBvRb/Dz0E5u2Af20T7VdebVsQ/G7Tdik38qrxabvtvJqsSkvK68W
m/Ky8mqyT1y78mqyT1y78mqxqR6tvJpqtS/tyqvFpndbeTXVGre3K68mRcQrNiLytE531a/unEaPzc8bsPk90K/z+6Kf60xEP80N
twmt1P+2Ca3U/7YJrcSIbUIr7UFr06aVvm9CK7drCa2ivltCq+h00Sr6eWilNaU2oVX2e6BV7/yhleZp2oRWg69DK/WhbaKsadzZ
wqu19j20Gf1cjzL6aS63zeinedY2o9/i56Gf69bKq6lx+7fyamp2tqGf62BGP41324x+mltqV14tz1NdyOincXG78mq5zs9DP7dN
K6+mRnMt7cqryT527cqryf557cqr5Trpt/Jqsel7rLyaGtctTndrNJ/T9ujX+Tr0a52/VT/7+7UrrxabNF15Ndkfse3RT+P7duXV
1CSngX4a67Urr6amtw39XHYH9NM8Zjugn+Yj2gH9NB5qB/TTHEU7oJ+4th3Qz2OBAf00F9QO6Od+dUC/6HTRL/o69POYYUA/zee0
A/ppvacd0M/1aOXVpIh4xYZ+s77biH7yPWxH9NO+uXbl1RIEQs8b0c997cqr5TqngX5aT25H9NMaabvyarnXNvRz/zuin+Z325VX
y73O86pfW/u6EZufh34e08CrrfsyeLVzewCvNm5f4NVWvkstvNpqbbaFV1v5dLXwqn2rWni1FW+18Grr/gNebd0fwatt77xkrtM3
h1dbj2PhVftGtvBqaw6AV9va74F+8hlt4dVWzNnCq63bRHjV/o0tvNq6n4ZX28HPo/xpz1MLr7ZuN+DV1u0zvNp63Amvtu4b4dXW
Y0d4tZ1UruDV1uV+Rj/NBbXwajvZhn6976X8ac6jhVdb+Ti18Grr9gBe7dw+w6ud22d41b6HLbzaVU4jYNN3g1e7yuminzkPXu3c
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
dXZZg1ftNxbg1VlzUAFetU9XgFfnxs8bsKn8wauz9sFHeHXWOW0RXp3Vn0d4dVZfEeHVWf1ChFdn9TMRXrX/VoRXZzFxhFfn4Oeh
Qe08o4HmqSO86nWwCK8qIl6xoYHmuSK8at+vCK/OqkcRXp215hrh1Vl9T4RXZzFEhFdnrXlFeHVWHxXhVftlRXh1FldEeNW+WhFe
nVXPI7yqyHnFhn69n4d+4u4Ir86aX4vw6qw57givzoOfh35qSyK8Ost/JsKrs/qjCK/OqvsRXp0n29BPdTrCq7PqdIRX58X3ot9s
G/ppzjzCq4v6mQivLju/x6rfUtk2YFNZg1cX+cBEeNXxoyK8ulR+jwXboY2I8Ooito/w6iLuifDqIoaI8Ooi/ojw6tL4eR025Rle
tX9ehFcXtVcRXnW8rAiv2o8vwquL2xx4dWmdZ/Rr/Tz009pYhFcXnTMb4VVFBiw2tHJbAq8ubpvgVUUQKza00vpWhFftwxbh1UXj
vwiv2q8twqvLoPeAVxf1qxFeXbQXIsKry+x3Q6vZ96LV7HRnzo1yupQ1zVXFlVfzzuWe9VX7l0V41TGl4sqr2TGlYua8KteZlVez
fb/iyqslXem38mq5V+Vg5dViU3lZeTXbXy2uvFrS0PuuvJp3je8dsTl/Eza/L2VNc3hx5dUy3S6de/Rzf7nyanacqbjyarYfWuzR
T2tysUc/15ke/VzfevQTi8ce/bT/Kvbo1/le9Au+Dv2C3w393NeuvFqms30v+rn/7bfyZxv6ic/jgH7ukwf0E7PHAf3crw7oJ26M
w3Zemt5jQD/neUA/19UB/dznDeindbU4oJ/r5YB+YqtItOfa46aB8uc+b+XVXO38vFW/yv3MyqvZsbbiyqtlGUfXrbxabNJv5dVc
eZy48mp2vKy48mqxKc8rr+bK7enKq9k+XXHl1WJz/lb9quh7MzbnedWv8lhq5dVi8/NGbL4X/Xrb0K/389DP33xCP4+lJvTzNyee
TaVzsuKEfoPvRT+tOcQJ/cTicUI/7VGKE/p5jASvVpOfh35isDih3+R3Q7/Z6aKfy9+Efh5fTei3WAP0016DuPJqrt1mz+gnjoor
r5brpN/Kq9kxueLKq+U6pbvyarHpPVZeLUuQTjdiUx+w8mquPaZZebXYpP3Kq9m+RnHl1Xyt/q68muvs5636Oe5XXHk1O55XXHm1
5E/fckE/j0FWXs2OtRUX9DNDLOinfaVxQT/NvcYF/cT2kfOWHJMrLujnscqCfrOvW/Vrdn4e+nl8sPJqbrSuG1dezY38rRL+q43a
tbTyarmulq3mul62husa2VYNmsbXddg62QK2QbZVg0ZjzLTyall23smGBtHX9Vznd0MDtbGpRYPBz1vLUNP7eTO2Sba1DDVixNSh
n75l6tBPbUTq0E9nfqcO/bTXIHXop7Fo6tBv8nXop/0WqUM/rZumDv3UhqUO/UY/D/1mv9uqX+tvvvJqsfm6CZvzsupnH5i08mq2
z0paebXcq/ytvFq2Qki/lVdzq/WZtPJqtj9EWnm1XFfJ1nGd3mPl1eyYV2nl1dxqnJhWXi3X6X1XXi3XOS+rfq3LaUC/4Oehn9rO
FNAvOH+0Ydo/mQL66byCFNFPe5RSRD/tXUgR/TT+S5wP3Kq9ShH9XLci+mnfQ4rop7Fjiuin8w/SyqvZsX/SyqvZe+3TyqvZ+/7T
yqvZ+/nTyqvFprKx8mqxqTyvvFps0m/l1XLkt/RbeTXbtyCtvFpsyt/Kq8Um/Tgf2HF+0sqrxaaysfJq9t79tPJqsUnThFby5UmJ
WMnq91NCK9f9hFaj84dWo/OHVvIPSPBqpz1ZaeXVYlO68Kr9AxLrq53GOSmjn9sweLXTuD3Bq463k+DVoPXVBK8G91vwqmOCJHg1
tE4jY3Oee2y+l/2sGjMkeDW4HsGrjreTVl4tNudvwabvAa/aZyDBq0H7mxK86lg4CV51HJ0Er4bkNNDPdQFeDRo3JXg1aN9hglft
W5Dg1eC6AK8GsVra9gMPzjP6ua+FVx3PJsGr9ktI8Kpj3CR41TFuErwa5JOZ4NWgsXyCV+2XkOBVx71Jw7Yfzjb0c7mHV73/PsGr
wXULXvWe/ASvOv5MWnk127cgwav2LUjwanRfC6/GnTVYuE7fCF6NGjsmeDVqjifBq9FjQnjVsXASvBq1lpDg1Sj+TfBqbPw89NM5
iwlejZprSfBqdP8Lr8bWeUY/8UKCV6PbA3g1ts4L+rlOw6v2S0jwahSnJHg1uv7Cq/YjSCuvdvbpT/Cq4/IkeDVqXTLBq46tk+DV
qHWSBK9G993wanQ/Da9G7Q1I8GpMfg/0S84f+mmOJ8GrMVsr9BNbJXg1uq+dt/05ShdejZrzTfCqfQYSvBrdlsCr0X0jvGo/ggSv
Ro+B4VX7SCR41TF4ErwadSZ+glcX9ynwqn0Q0rydz+/r0M99PLwaNQeQ4FX7KiR41TF9EryatC83wavJ9RdetX9AgleTfH4SvJpc
V+HV5DoIryZrAK8m96vwqvfpJ3g1Bd+76pc03s3walL9yPCqYwlleDVp7ivDq47zk+FVx/nJ8Kr3t2d4NamPyvCq97dneNX74DO8
6hhBGV5NYvsMryatoWV4Ne/8vAmb713LkGPwZHg1i9UyvJrlx5zh1axykOFV79nO8Kr3o2d4NddOo8Om7wavOs5Phldz7eet+uXG
6WZsvm7VL6ttz/BqVtue4dWsOagMr+bO+UM/ldMMr2atJWR4NYsRM7zqPe8ZXnUsoQyvZo25Mrzq/d4ZXs2970U/8UeGVx37J8Or
eXBe0E9tToZXs+YiM7zqfdcZXs2T84d+k3VBv9n3op/ikmV4NWs/a4ZXs9rJDK9mrTFneNV7uzO82u/8vA6b3hde7bXWluHVPDvd
VT/HEsrwal87L6t+jvOT4dXeZQ1e7V1O4dVePv0ZXnWMoAyvOr5Qhld7lyt4tdeYNcOr3j+e4VXHHMrwai8myfCq93tneLUPThet
NB7KCa20DpHh1T44L2ilOY8Mr/Yu4/Cq4/xkeLV3GYdXe839Z3jV8XYyvNq77MKrjreT4dVeTJzhVe+TzvCq+/MMr3rfdYZX+9lp
oJ/OIc3waj/7eejnfgFe7V234NV+cZ7Rz/UNXvUe8Ayv9q5v8Krj8mR41TF4Mrzq/d4ZXh20tyLDq4PmlTO8OmgOOcOrg/wmMrw6
aI05w6vei53h1UHzZhleHWrnb8Am/eDVoXaeJ2IjOM+rfoOYJMOrg+svvOr93hledTygDK96D3iGVwf3PfDqoPXBzPqq92JneNX7
pDO8OiTb0C87DfTT/FqGVwf3W/Cq4/dkeHXQ/FqGV4feeUa/wXlGP9dfeHXQfFiGVwfNAWR41TFzMrzqeDsZXh1c9+HVQVyW4dXB
dRVeHVyn4dVBc+YZXh3cbsCrw+x0V/289zzDq4P7QXh1cP2FV4fFWq36jVq7y/CqY/9keHX02BFedayezPrqKK7I8Oro9gBeHTVH
keHV0WNReHXUvq8Mr44752/Vb3S9hFdH7cnK8OroNgJeHT0WhVdHj23h1VFzFBleHbVvM8Oro+s+vDqKezK8OrqfhldHza1neNXx
lDK8Ogani37RaaCf9vhneHWcfS/66RyMDK+OLi/w6uRyAK9O/pasr47ue+DVyUwCrzqWS4ZXJ7e78OpU+7pVP8fSyPDq5H4BXp3c
p8Crk9tieNWxYTK8OrlMwquT1oAyvOr4Lhlenfx94VXHd8nw6qQ5qB5enTQP3MOrk+aLe3h10liqh1cn9QE9vDqJXXp4ddJ+4B5e
dbyYHl51LJceXp20FtPDq46L0sOrk/i8h1cnzSP18OqUbZt4nt+NMtQ7L5QhzSH38Ookxu7h1Ul7Onp4ddK6Sw+vOvZKD696/30P
r07qP3p41Xvye3jVe/x7eHWSn3oPr04aT/bw6rQ4L+g3O130E0f18Oo0Oy/ot/i6Vb9Z47AeXp3VdvbwqvfQ9/DqrHXEHl51/I8e
XnUcjh5e9d7uHl51zI0eXvWe7R5edcyNHl51zI0eXp2z8zdgc7ojNudv1W/ufe+Mze+Gfi4v8Kr3e/fw6ixO6eM256u8wKuz1t96
eHXWekUPr84ua/DqrHX7Hl6dNbbo4dV5chroNzkN9JucZ/SbnQb6ae2uh1fn2bqgn8skvDqLP3p4ddbcZg+vzuKPHl6dtU7Sw6ve
Z97Dq96P3sOrs+sCvLrsnAb+R+rfeuLZhMHXrVp573kPry4aR/Tw6lI7L6tW3p/dw6uL9v/18OqieaQeXnVclB5e9X7qHl51XJQe
XnVclB5eXVwm4dVF6xU9vOq4KD28umi9sYdXFzF7D68u0fein/seeHWJThf9XKfhVe8L7+HVpfe7XepXthVIg5VXi1us8nK1H1jl
ing2rfvalVe7yvWIeDbVxR6C7z/76KOPfv7Tn/7050fff/y4/O0oH/3051geffXi2ZfnJ8+fPfrm+ZMXT/ePj/bfffv89Pzs8dHn
n/9l/8W3x1/+++en+z+9ODndf/75x0f/8dFHP3lxtj86Oz89+fL8J+XRv/zij/svzz95sv/q5Nn+V6fPv92fnr98dPWUn3z++f7s
Xy+f/ZPHR/9x9Ofjpy/2nx6dn77Yl+x89tGfj0+P/mn/bF8e90/L59XRL25L91F188pfPX/68s6r63L19l5Hpy+ezS++fHryZH/8
rH/69fPTk/M/fPPoq5P90yePj44fH33x+OjXF+91Id1FEp8ff3b595///Kg/O3vxzf7o+L+dHT3Zf3263x+dnB39918cffHfzi4v
Ofnq6NHxJ+tPjz4++sejL67+sT3x4v8+Py75/F1J5/j35X8XeT7+3a789Yv1r9Xv1wS/v8rC6b8cn52XH8nJpan884vDP8+54vI1
Pvk/+9Pn+u3K/vzZ/updfv3i2dGVDkfHmxBHL56dnzw9Or32ik/3Z2dH538o1/365/XlA/7yh5On+6NHp4eXLTL8+ujnR7Vf9Crv
5O7y759d+/lcP59f/3l769OD6erKg6m8ynTy5/IWSumLl+s/Hh/9pbzT0Z9ePD8/2T87Pzp5dvSno+NnT45O998cnzx7sj+9MJ1e
Pevi+13e+MnJ2f9XNLz+2UjtNtGOn57uj5+8PDrfn35z8uz4fP/k/7l22+n+/MXps6NnL54+PeT8+8Obbtq8qs+fbvmo229P9s+e
Xyb3/PRfSvInz77+bUl/e9YnX+/Px+f7r746+fLi5Xmxq/J441FPz//52Z/3p6Umb+mdrP9+dHsquv/WsnA9taO///ujvzu9U9X1
ZS4unU6++uriBQ53/sONR332yp1nXx4/PWT7mxdPz0++ffqy5OemAIeXf6wXvvHEC8H/9Mnxkye/PP3Niy/OT4+/PF8bh0++eHHy
9Mm/Pr9Q4/jpo0N+H685+PjGgy4/6o0Hra+yZXF4+WZPOxSU88vMbfdftHmPLsvMxzfSuapVespl4X7NN7r5UV5TZg8t09nJ198c
/7bosu/PL77tRd28qfuOTFxk4NXrf/GLo52TfiXZQ2Ind5TQmw8lPZ70u4Pgj7ijfP/TV42l2f3+0E2U3uvJfHpaCv3zL48vLGdb
H7G/sj4/3XJe2oXf/qG0lOX/j4+elF7ny/Oj42+/fXqy3nv0/Kuj8Q9FjdKsnu2PT7/8w9VLPXvxzWUyZ+W1/OQbBf5CPF1aVKtu
Ue13155w4ztUH7/asezPigol5Wf7vxz1p6fHLw+JfHzoQS6fOj4vXUO5dLfav3p+evTo8qsUW/VZ+c8/8lnOTv7P/qLC665/PLxm
ufJnP3PWL97sWrb3F0OC0ob2549OPn61gKyve5Hv3x1S+P0rheLkRnU8XPuzn91enq8ysub570rCBzH+8xKKec3a7UXpX4+/fnZy
/uLJ/npZmtcXfn7qsnVR4m4pXWvZevrysnS9LI3x0fL89Nn+ZSlY5S+lTB8f6ua1EnXxvE+e7p99ff6Hz173/bfvfu377tbv++rH
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
XUd/qyf8aJvk3rTvb9/TqVnvA5HCj4FI928W8323BoQfbGvAG7UOIY13uzLW9VsvUpXW4cHOFL9u/1R13xXEqv6xOq03bh3CQ3Gh
iPcdO7xmGP/jLWFfHxe27+zstVJrY5zvPpCgbt52baf8r9o92OnV9m0nR99qgrb+EF1u2jfc1vOaJ6QH3IlW924f2h+jfbj/i9/b
/bBq3y9cpHm8+wSjun0buCg5T7uLhujB7vMNb8sGb0UX6UP0im3vXSzf4V6Xh9AQhQ+yIWp298WY+v1iTK7m6u52qHsrt8fSDl0M
iKof6TTPe7mU7u49y7F7wDs/0r0HRM0HOSC6Ny/V9QfZDNX1h7bprl+2UOy3tUPhrVecL9qhBzvb+rqZ7Psf3FU95FWAfN+td+0H
ufWuTn+b07pN83DO4XqjdmjYpfnudii+9brzRTuUHiqXpbed3nmrKaaHvCGr/iB9EN7hB6/fbBtIHd5yRPVAePT+B9Wn9zseGseq
v7sdSn/V8tLji2r9IfqCx3vvD3jIk0TNfdui+sNsjNr7wllTfZiT1dV9G6Omer+N0dQ0y92NUX5rj6jLVbOL1ujBzljHe++HiT/O
fph7j4yq+7ZG8cOcsb7vyKiJH+bIKN97ZBTeb2M0T7G7OyTg7m1GRvXWGF1MW7+zIFTv0k3qB9g6+S7PyXmX00X3HhQ+6JX8e+8S
rrsPc+b63u7ir3nxd9IeLXW3u7s9qt7aWfOiPbpolN5ZyK37F877n9vVfJjtUX3f2es6/xjT1/dHtfre6/l/q63R+503qnd5es3o
qH6b+evdto520SQ16QEEXHmdH37VPZgt/Pc+XuJ1EzoPuJV4zYu/6YzOhzlouT9ENe930FJXYXnNoKX565bbyx/tg51f/s/ajod7
2Oi926P23u1R9UG2R68ZbNX3Pnfhv/YMc/t+J3XqOg13L3c17V+37H7RHoX/whAV/mbbow9zfNS2H+QBpPefv7y3b2f1XjcB1U3M
d693Nd091rvKH92DnWd+3S6J+t5+ng/ZYew1b/6G88yvWQV5yPPMTf4b9Ri7/w7p9v0uwtftsLt7h3QT3iKY9uWOoHDVKF00T137
AfqOvWGb9DrXvofcKIX7tknNh+nF2oZ7t0m7D7NNum+TFN6vE2vdtfXdm6Wb+Nc5sV5MNl+0S136EKeS/ovvm763+0bVfpjolv9W
26T2Q5tKCn2427O+SX+dR+tFo3TRMoUP8rCPNzxbN32YjVLV3LdRauoPs1FKf6Pw1t57pNS833Djdezau93sm/w2mxZbNgmtjdIF
vD3cAH/17m/15I92d196ix8mvDV/oy73r9ti+4b0Ft9vm5TGcPcJhu3uHnsAyh/x4c5y57dtUd5q4e0BB96q7n0MyGscjx70LPf9
Xc0+0Fnu+zdK72KW+/efffTRRz//6U9/+vOj7z9+XP52EYf5pz/H9OirF88u24lH3zx/8uLp/vHR/rtvn5+enz0++vzzv+y/+Pb4
y3///HT/pxcnp/vPP/+4iPnRT16c7Y/Ozk9Pvjz/SXn2L7/4Y2lpPnmy/+rk2f5Xp8+/3Z+ev3x09ZSffP75/uxfL5/9k8fldf98
/PTF/tOj89MX+5Kfzz768/HpUWkl//W4PPC7z6ujX9yW7qNduXLL6dHZn14cn+5/+/x/vjh+cnry9Li0j8dPH31bxPu2tIbflk7x
2/ZjPvvF459815THflt98t3RP5RLyn9+Vq5a/9V+8t1nhwtfcuHL9cKX64Uv1wtfrheefHX06PKJv/jF0e7o7/9+veviHyXNo5//
/Kj/6kKJqy9xuj9/cfrsRik8rqpP16z8w2XGHt/4tf50Tf/y15c3f21Kl3LDVl88r7l6w5u/1p9evUj9yvPqW57XXDzv1Yw19ae3
5ahpLpaNr2zfr0p9f/ln6X32evv1g1x85+31m+0THH6uL35u7/r5JXe/XH9+efNn7r7j5/2z59+cPDs+f35aLrvIyU8vb/mHy2Qv
/l5dv6HIXS68/OQ3r2w+Pvq5H3jjxpob1ySayxvXh1R33vhGpaUUy4tc/fS2T32j6PjS28pR+eO2ktReS6u+fEB7e7Fqr6W1XXpb
GTuum3dSyr4/NA1/cpPw2+e/uWwp7mgaSlX9H/vT0uKd/2F/dPzkj89Pnp0fne1P/7w/Ozo+u7SePLsYqe0/vWohzkqrUz7qG7VA
a/Ze+aCXH/PiOZ8U/YpY61+bi+KBtTlYvYf84suu5spXXN1X+Wm+r/n01SvqQ3p62rWjtOtDPpVedchndXt69SGf1W3v59zbY6du
bnm/+pCennbt8ODmkM/qNl2sstNr6lt0aW5N79p3aJpb3q++9TtsgQtKUVUhPT/5Zn/26Pjx0RdbUby9kByTwheX//3Zxb/r7d/1
+u9m+3dzo6Ackw/fW9+4t77t3ma9t7lxb3Pj3uaWe+vrea5v5Lm+kef6ZqFRnusbea5v5Pn6vdfzXN/Ic30jz68UHuW5uZHn5kae
rxX05nqemxt5bm7k+fq91/Pc3MhzcyPP273XC9L+u/PT4y/PH518c/x1acfKSPH4wu6xz59KI1garNvbxf84+q6Mez8p2+FfXv63
DBePLm3bkz55UorqswtULaX7jS8MXHjXj1d3N6+78DKZjz97s6b36gnnz7/9l/1X5wcxLiy/Pvn6DzbdZGz99MXz8/Pn31w8QkkX
lZ+dffX89JuS/lp5LzLz+FJcXfbN5Ri2XKPx7CdXf//ky9N9ye38zbdlePzqGz++RYVrz/7225NnXy/bp//F0VUpePRdEfHjm0Os
a8OcqxegxF306rJdlrqX121N858MSsr3e+TnVrc8t7rluTfHPtc7+Zc3nlrf8tT6lqfWdz51Gyas/ymXHz26EOhlkWX3WfnPP94i
fLH/7GeW9Oq279bbvrvjtu+u37Z9je/+9wX1lFsvXmX3SffZK1e83K54edcVZ89fnH65/9XJd/un5bIb5eHRmsJjnvPx9dvXgvnJ
2f78sqw8PrpsMD75uvy7lM0/fPLV0+fPTx8pgU+++/jx0R0/vfz4Yz3+e430Xykma7qf8t/Hsl/L/Kc3DWrr4MhPaOrKm/O3V6m2
fmBU+6/9//v58s//Ns2//lX/29/Ov/6333z+219+/pu5//X4P8p7tFz1z//2+f/8X/30+a/73/7zLy9K18XH3+6/9ku1/fLk5Oz8
+NmX+2utAOOJ7Stcfr2zP53yib99/pdHj764HNUfX37dUmF+duSfXl7+9PLyp48/u1D/ANwvvnl0+YZnNwYsq/GT0/2TF1/uH92Z
l+OS1BefXQrz/Udl2P3b43/fXwywT/f7o6Lvk/3p0bdrS1xG3s+eHD0//fr42cn/ubxm/00ZhZ8/P7pq2A/t+f78y0MeT/dlwmR/
ulw+jnb97BGPvRiYr3+rr/7WuJv8vOT48y/K/74s/3vy2cYHF0+7Uvvs6Iv9+V/2+2fbE46+XOdmr57y/Nn+t395Ph2+znbrLflw
9/KX57+90OI1Nzrbn11L7z+5sbr1xkMvp1ysAl8zXAp9pUZ/VgrC/iLVoy+fPj/bn52Xa46el290+Q5HJ2dHw2dH/eUnHI/+cvL0
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
"""
_jsqr_cache = []


def jsqr_source():
    """Decompress the embedded jsQR and check it's the untouched original."""
    if not _jsqr_cache:
        import base64
        import zlib
        try:
            src = zlib.decompress(base64.b64decode("".join(JSQR_B64.split())))
            if hashlib.sha256(src).hexdigest() != JSQR_SHA256:
                raise ValueError("checksum mismatch")
            _jsqr_cache.append(src.decode("utf-8"))
        except Exception:
            _jsqr_cache.append("/* jsQR unavailable - scanning falls back to the browser's own QR reader */")
    return _jsqr_cache[0]


WEB_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Shardrip</title>
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0b1220">
<style>
:root{--bg:#0a0f1a;--top:#0b1220;--card:#0f1828;--line:#1d2a40;--input:#131e31;--input-line:#22314b;
--fg:#e7eef8;--head:#f3f7fd;--muted:#8ea3bf;--label:#6f86a6;--ph:#51657f;--accent:#00c2f5;--accent2:#33d0fa;
--accent-ink:#03131f;--danger:#ff6b6b;--amber:#fbbf24;--log:#0a1220;
--font:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--fg);
font:14px/1.5 var(--font)}
body{background:radial-gradient(1200px 500px at 50% -200px,#10203a 0%,var(--bg) 60%) fixed,var(--bg)}
::selection{background:#00c2f544}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#22314b;border-radius:8px;border:2px solid var(--bg)}
::-webkit-scrollbar-track{background:transparent}

/* top bar */
.top{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:16px;height:54px;padding:0 18px;
background:rgba(11,18,32,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;color:var(--head);letter-spacing:.2px}
.logo{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;font-size:15px;
background:linear-gradient(135deg,#00c2f5,#2563eb);box-shadow:0 0 0 1px #ffffff1a inset,0 4px 14px #00c2f533}
.tabs{display:flex;gap:6px}
.tab{padding:6px 14px;border-radius:7px;border:1px solid var(--input-line);background:transparent;color:var(--muted);
font:600 13px/1.2 var(--font);cursor:pointer;transition:.15s}
.tab:hover{color:var(--fg);border-color:#2f4466}
.tab.on{color:var(--accent);border-color:var(--accent);background:#00c2f514}
.ver{margin-left:auto;font:12px ui-monospace,Consolas,monospace;color:var(--label);border:1px solid var(--line);
border-radius:20px;padding:3px 10px}

/* cards + fields */
main{max-width:640px;margin:0 auto;padding:28px 16px 48px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px;
box-shadow:0 10px 30px rgba(0,0,0,.25)}
.card h2{margin:0;font-size:21px;font-weight:700;color:var(--head);letter-spacing:.2px}
.sub{margin:4px 0 6px;color:var(--muted);font-size:13px}
label{display:block;margin:16px 0 6px;font:500 11px/1.2 ui-monospace,"Cascadia Mono",Consolas,monospace;
text-transform:uppercase;letter-spacing:.09em;color:var(--label)}
input[type=text],input[type=password],input[type=number],select{width:100%;min-width:0;padding:11px 13px;border-radius:8px;
border:1px solid var(--input-line);background:var(--input);color:var(--fg);font:14px var(--font);outline:none;transition:.15s}
input::placeholder{color:var(--ph)}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px #00c2f526}
input[readonly]{color:#bcd0e8;font:13px ui-monospace,Consolas,monospace}
.row{display:flex;gap:8px;align-items:center}.row>input{flex:1}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
button{padding:11px 16px;border-radius:8px;border:1px solid var(--input-line);background:transparent;color:var(--muted);
font:600 14px var(--font);cursor:pointer;white-space:nowrap;transition:.15s}
button:hover:not(:disabled){color:var(--accent);border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:700}
button.primary:hover:not(:disabled){background:var(--accent2);border-color:var(--accent2);color:var(--accent-ink);
box-shadow:0 6px 20px #00c2f540}
button.stop:not(:disabled){color:var(--danger);border-color:#ff6b6b55}
button.stop:hover:not(:disabled){color:#fff;background:#ff6b6b22;border-color:var(--danger)}
button:disabled{opacity:.4;cursor:default}
.actions{display:flex;flex-direction:column;gap:8px;margin-top:20px}
.check{display:flex;align-items:center;gap:10px;margin:16px 0 0;font:500 14px var(--font);text-transform:none;
letter-spacing:0;color:var(--fg);cursor:pointer}
.check input{width:18px;height:18px;accent-color:var(--accent);margin:0}
.grid2 .check{margin-top:38px}
.note{margin-top:12px;padding:10px 12px;border-radius:8px;border:1px solid #f59e0b66;background:#f59e0b12;
color:var(--amber);font-size:13px}
.bar{height:10px;background:var(--input);border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-top:20px}
.bar>div{height:100%;width:0;background:linear-gradient(90deg,#00c2f5,#2563eb);transition:width .4s}
.status{margin-top:10px;font-size:13px;color:var(--muted);word-break:break-word}
pre.log{background:var(--log);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:14px 0 0;
max-height:200px;overflow:auto;color:#9fb2cc;font:12px/1.55 ui-monospace,"Cascadia Mono",Consolas,monospace;
white-space:pre-wrap;word-break:break-all}
pre.log:empty{display:none}

/* sharing */
.links{display:grid;gap:4px}
.lnk .t{margin:12px 0 6px;font:500 11px/1.2 ui-monospace,Consolas,monospace;text-transform:uppercase;letter-spacing:.09em;color:var(--label)}
.lnk .t b{color:var(--accent);font-weight:600}
.share{display:grid;grid-template-columns:1fr 200px;gap:18px;align-items:start;margin-top:6px}
.qr{background:#fff;border-radius:12px;padding:8px;margin-top:12px;box-shadow:0 0 0 1px var(--line),0 8px 24px rgba(0,0,0,.35)}
.qr svg{display:block;width:100%}
.qrcap{text-align:center;font-size:12px;color:var(--muted);margin-top:8px}
.seg{display:flex;gap:6px;flex-wrap:wrap}
.seg button{padding:8px 12px;font-size:13px}
.seg button.on{color:var(--accent);border-color:var(--accent);background:#0c2433}
.qrsw{margin-top:8px;gap:4px}.qrsw button{flex:1;padding:6px 4px;font-size:12px}
.vhint{font-size:12px;color:var(--muted);margin-top:6px}
.pw{color:var(--amber)!important;font:600 15px ui-monospace,Consolas,monospace!important}
.hint{font-size:13px;color:var(--muted);margin-top:10px}

/* sheets (pickers, questions, scanner) */
.modal{position:fixed;inset:0;background:rgba(3,7,15,.7);backdrop-filter:blur(3px);display:none;align-items:flex-end;
justify-content:center;z-index:9}
.modal.on{display:flex}
.sheet{background:var(--card);border:1px solid var(--line);width:100%;max-width:560px;border-radius:16px 16px 0 0;
padding:20px;max-height:88vh;display:flex;flex-direction:column;box-shadow:0 -10px 40px rgba(0,0,0,.4)}
@media (min-width:640px){.modal{align-items:center}.sheet{border-radius:16px}}
.sheet h3{margin:0 0 10px;font-size:17px;color:var(--head)}
.sheet p{color:var(--muted)}
.sheet .actions{flex-direction:row}.sheet .actions button{flex:1}
.crumb{font:12px ui-monospace,Consolas,monospace;color:var(--label);word-break:break-all;margin-bottom:10px}
.list{overflow:auto;border:1px solid var(--line);border-radius:10px;flex:1;min-height:160px;background:var(--log)}
.item{display:flex;justify-content:space-between;gap:8px;padding:11px 13px;border-bottom:1px solid var(--line);cursor:pointer}
.item:last-child{border-bottom:0}.item:hover{background:var(--input);color:var(--accent)}
.item small{color:var(--label);white-space:nowrap;font-family:ui-monospace,Consolas,monospace}
.cam{position:relative;background:#000;border-radius:12px;overflow:hidden;aspect-ratio:1/1;max-height:58vh;margin:4px auto 0;
width:100%;border:1px solid var(--line)}
.cam video{width:100%;height:100%;object-fit:cover;display:block}
.cam .frame{position:absolute;inset:18%;border:3px solid var(--accent);border-radius:16px;box-shadow:0 0 0 999px rgba(0,0,0,.45),0 0 24px #00c2f566}
.toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);background:var(--card);color:var(--fg);
border:1px solid var(--accent);padding:10px 18px;border-radius:10px;font-size:14px;opacity:0;transition:opacity .2s;
pointer-events:none;z-index:10;box-shadow:0 10px 30px rgba(0,0,0,.4);max-width:90vw;text-align:center}
.toast.on{opacity:1}
@media (max-width:540px){
  .top{padding:0 12px;gap:10px}.brand b{display:none}.ver{display:none}.tabs{margin-left:auto}
  main{padding:16px 10px 40px}.card{padding:18px 16px}
  .share{grid-template-columns:1fr}.qr{max-width:240px;margin:12px auto 0}
  .grid2{grid-template-columns:1fr}.grid2 .check{margin-top:16px}
}
</style></head><body>
<header class="top">
  <div class="brand"><span class="logo">⚡</span><b>Shardrip</b></div>
  <nav class="tabs"><button class="tab on" data-t="dl">⬇ Download</button><button class="tab" data-t="send">⬆ Send</button></nav>
  <span class="ver">v__VERSION__</span>
</header>
<main>

<section id="dl" class="card">
  <h2>Download a file</h2>
  <div class="sub">Paste a link, or scan / upload a Shardrip QR code.</div>
  <label>Download URL:</label>
  <div class="row"><input type="text" id="url" placeholder="https://… direct file link" autocomplete="off"><button id="scanBtn" title="Scan or upload a Shardrip QR code">📷 Scan QR</button></div>
  <label>Save to:</label>
  <div class="row"><input type="text" id="folder"><button id="pickFolder">Browse</button></div>
  <div class="grid2">
    <div><label>File name:</label><input type="text" id="name" autocomplete="off"></div>
    <div><label>Connections:</label><input type="number" id="conns" min="1" max="32" value="16"></div>
    <div><label>Password (locked files):</label><input type="password" id="dlpw" autocomplete="off" placeholder="only if the file is locked"></div>
    <div><label>SHA256 (optional):</label><input type="text" id="sha" autocomplete="off" placeholder="to verify the file"></div>
  </div>
  <label>Extra mirrors (optional):</label><input type="text" id="mirrors" autocomplete="off" placeholder="more links to the same file, separated by spaces">
  <label>Connect via (for Shardrip smart links):</label>
  <div class="seg" id="via"><button data-v="auto" class="on">Auto</button><button data-v="lan">Same network only</button><button data-v="internet">Internet only</button></div>
  <div class="vhint" id="viaHint">Same Wi-Fi as the sender → direct &amp; fast, otherwise internet.</div>
  <div class="actions"><button class="primary" id="dlStart">⬇ Start download</button><button class="stop" id="dlStop" disabled>■ Stop</button></div>
  <div class="bar"><div id="dlBar"></div></div>
  <div class="status" id="dlStatus">Ready.</div>
  <pre class="log" id="dlLog"></pre>
</section>

<section id="send" class="card" hidden>
  <h2>Send a file</h2>
  <div class="sub">Share a file from this device with a link - no port forwarding needed.</div>
  <label>File to send:</label>
  <div class="row"><input type="text" id="path" placeholder="pick a file…"><button id="pickFile">Browse</button></div>
  <div class="grid2">
    <div><label>Port:</label><input type="number" id="port" value="8080" min="1024" max="65535"></div>
    <div><label class="check"><input type="checkbox" id="public" checked> Public internet link</label></div>
  </div>
  <label class="check"><input type="checkbox" id="lock"> 🔒 Lock with password</label>
  <div class="row" id="pwrow" hidden style="margin-top:10px"><input type="text" id="sendpw" autocomplete="off"><button id="gen">Generate</button></div>
  <div class="note" id="lockNote" hidden>🔒 Send the password <b>separately</b> from the link - e.g. text the link, say the password. The receiver needs Shardrip to unlock it.</div>
  <div class="actions"><button class="primary" id="sendStart">⬆ Start sharing</button><button class="stop" id="sendStop" disabled>■ Stop sharing</button></div>
  <div class="status" id="sendStatus">Pick a file and press Start sharing.</div>
  <div class="share" id="shareBox" hidden><div class="links" id="links"></div>
    <div><div class="qr" id="qr"></div><div class="seg qrsw" id="qrsw"></div><div class="qrcap" id="qrcap">Scan with a phone camera</div></div></div>
  <pre class="log" id="sendLog"></pre>
</section>
</main>

<div class="modal" id="browser"><div class="sheet"><h3 id="bTitle">Choose</h3><div class="crumb" id="bPath"></div>
  <div class="list" id="bList"></div>
  <div class="actions"><button id="bUp">⬆ Up</button><button class="primary" id="bUse">Use this folder</button><button id="bClose">Cancel</button></div></div></div>
<div class="modal" id="ask"><div class="sheet"><h3>Shardrip</h3><p id="askText"></p>
  <input type="password" id="askPw" hidden autocomplete="off">
  <div class="actions"><button class="primary" id="askYes">OK</button><button id="askNo">Cancel</button></div></div></div>
<div class="modal" id="scanner"><div class="sheet"><h3>Scan or upload a Shardrip QR code</h3>
  <div class="cam" id="scanCam"><video id="scanVideo" playsinline muted></video><div class="frame"></div></div>
  <div class="hint" id="scanHint">Point the camera at the QR code, or tap “Upload QR image” to use a screenshot or photo of it.</div>
  <input type="file" id="scanFile" accept="image/*" hidden>
  <div class="actions"><button id="scanPhoto">🖼 Upload QR image</button><button id="scanClose">Cancel</button></div></div></div>
<div class="toast" id="toast"></div>
<script>/*__JSQR__*/</script>

<script>
const KEY = new URLSearchParams(location.search).get("key") || "";
history.replaceState(null, "", "/?key=" + encodeURIComponent(KEY));
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(path, body){
  const r = await fetch(path, {method: body ? "POST" : "GET", headers: {"X-Shardrip-Key": KEY, "Content-Type": "application/json"},
                               body: body ? JSON.stringify(body) : undefined});
  const j = await r.json().catch(() => ({error: "bad response"}));
  if (!r.ok) throw new Error(j.error || r.status);
  return j;
}
function toast(t){ const e = $("toast"); e.textContent = t; e.classList.add("on"); setTimeout(() => e.classList.remove("on"), 1600); }
async function copy(text){
  try { await navigator.clipboard.writeText(text); }
  catch (e) { const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select();
              document.execCommand("copy"); t.remove(); }
  toast("Copied ✓");
}
document.querySelectorAll(".tab").forEach(b => b.onclick = () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("on", x === b));
  $("dl").hidden = b.dataset.t !== "dl"; $("send").hidden = b.dataset.t !== "send";
});

// ---- download ----
let nameAuto = true;
$("name").oninput = () => nameAuto = false;
$("url").oninput = () => { if (!nameAuto) return; try { const u = new URL($("url").value.trim());
  $("name").value = decodeURIComponent(u.pathname.split("/").pop() || ""); } catch (e) { $("name").value = ""; } };
let via = "auto";
const VIA_HINT = {auto: "Same Wi-Fi as the sender → direct & fast, otherwise internet.",
  lan: "Only over the local network - fails away from it.", internet: "Always through the internet link."};
$("via").onclick = e => { const b = e.target.closest("button[data-v]"); if (!b) return; via = b.dataset.v;
  for (const x of $("via").children) x.classList.toggle("on", x === b); $("viaHint").textContent = VIA_HINT[via]; };
$("dlStart").onclick = async () => {
  try { await api("/api/download", {url: $("url").value, folder: $("folder").value, name: $("name").value,
          connections: +$("conns").value, password: $("dlpw").value, mirrors: $("mirrors").value, sha256: $("sha").value,
          via});
        $("dlBar").style.width = "0"; }
  catch (e) { toast(e.message); }
};
$("dlStop").onclick = () => api("/api/download/stop", {}).catch(e => toast(e.message));

// ---- send ----
$("lock").onchange = () => { $("pwrow").hidden = $("lockNote").hidden = !$("lock").checked; if ($("lock").checked && !$("sendpw").value) gen(); };
function gen(){ const a = "abcdefghjkmnpqrstuvwxyz23456789", r = new Uint32Array(16); crypto.getRandomValues(r);
  $("sendpw").value = [0,1,2,3].map(g => [0,1,2,3].map(i => a[r[g*4+i] % a.length]).join("")).join("-"); }
$("gen").onclick = gen;
$("sendStart").onclick = async () => {
  try { await api("/api/send", {path: $("path").value, port: +$("port").value, public: $("public").checked,
                                 lock: $("lock").checked, password: $("sendpw").value}); }
  catch (e) { toast(e.message); }
};
$("sendStop").onclick = () => api("/api/send/stop", {}).catch(e => toast(e.message));

// ---- file browser ----
let bMode = "file", bCur = "";
async function browse(path){
  try { const d = await api("/api/ls?path=" + encodeURIComponent(path ?? ""));
    bCur = d.path; $("bPath").textContent = d.path || "This PC";
    $("bUp").disabled = d.parent === null;  $("bUp").dataset.p = d.parent ?? "";
    $("bList").innerHTML = d.dirs.map(x => `<div class="item" data-d="${esc(x.path)}">📁 ${esc(x.name)}</div>`).join("") +
      (bMode === "file" ? d.files.map(x => `<div class="item" data-f="${esc(x.path)}"><span>📄 ${esc(x.name)}</span><small>${esc(x.size)}</small></div>`).join("") : "") ||
      `<div class="item"><small>Empty folder</small></div>`;
  } catch (e) { toast(e.message); }
}
$("bList").onclick = e => { const it = e.target.closest(".item"); if (!it) return;
  if (it.dataset.d !== undefined) browse(it.dataset.d);
  else if (it.dataset.f) { $("path").value = it.dataset.f; $("browser").classList.remove("on"); } };
$("bUp").onclick = () => browse($("bUp").dataset.p);
$("bUse").onclick = () => { if (bCur) $("folder").value = bCur; $("browser").classList.remove("on"); };
$("bClose").onclick = () => $("browser").classList.remove("on");
function openBrowser(mode, start){ bMode = mode; $("bTitle").textContent = mode === "file" ? "Choose a file to send" : "Choose a folder";
  $("bUse").hidden = mode === "file"; $("browser").classList.add("on"); browse(start); }
$("pickFolder").onclick = () => openBrowser("folder", $("folder").value);
$("pickFile").onclick = () => openBrowser("file", $("path").value ? $("path").value.replace(/[\\/][^\\/]*$/, "") : "");

// ---- questions from Shardrip (overwrite? password?) ----
let askId = null;
async function answer(v){ const id = askId; askId = null; $("ask").classList.remove("on");
  await api("/api/answer", {id, value: v}).catch(() => {}); }
$("askYes").onclick = () => answer($("askPw").hidden ? true : $("askPw").value);
$("askNo").onclick = () => answer($("askPw").hidden ? false : "");
$("askPw").onkeydown = e => { if (e.key === "Enter") $("askYes").click(); };

// ---- live status ----
let shownShare = null, shownQrs = [], appMode = false;
function setLog(el, lines){ const atEnd = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
  const t = lines.join("\n"); if (el.textContent !== t) { el.textContent = t; if (atEnd) el.scrollTop = el.scrollHeight; } }
async function poll(){
  try {
    const s = await api("/api/status");
    const d = s.dl, p = d.progress;
    $("dlStart").disabled = d.running; $("dlStop").disabled = !d.running;
    if (p) { $("dlBar").style.width = (d.result ? 100 : p.pct) + "%"; }
    $("dlStatus").textContent = d.running && p ? `${p.label ? p.label + ": " : ""}${p.pct}% · ${p.done} / ${p.total} · ${p.speed}/s (${p.mbps} Mbps) · ETA ${p.eta}` : (d.status || "Ready.");
    setLog($("dlLog"), d.log);
    const se = s.send;
    $("sendStart").disabled = se.running; $("sendStop").disabled = !se.running;
    $("sendStatus").textContent = se.stats ? `Sharing ✅  Sent ${se.stats.sent} · ${se.stats.speed}/s (${se.stats.mbps} Mbps) · ${se.stats.active} active connection(s)` : (se.status || "Pick a file and press Start sharing.");
    setLog($("sendLog"), se.log);
    const sh = se.share, key = sh ? sh.links.map(l => l.url).join() : null;
    if (key !== shownShare) { shownShare = key; $("shareBox").hidden = !sh;
      if (sh) {
        let rows = sh.links.map((l, i) => [l.label, l.url, i === 0]);
        rows.push(["Receiver runs", sh.receiver_cmd]);
        if (sh.password) rows.push(["🔒 Password - send it separately from the link", sh.password, true, true]);
        else if (sh.sha256) rows.push(["SHA256", sh.sha256]);
        $("links").innerHTML = rows.map(([t, v, b, pw]) => `<div class="lnk"><div class="t">${b ? "<b>" + esc(t) + "</b>" : esc(t)}</div>
          <div class="row"><input type="text" readonly value="${esc(v)}" class="${pw ? "pw" : ""}"><button data-c="${esc(v)}">Copy</button></div></div>`).join("");
        $("qr").innerHTML = sh.qr; $("qrcap").textContent = "Scan with a phone camera";
        const qrs = sh.qrs || []; shownQrs = qrs;
        $("qrsw").innerHTML = qrs.length > 1 ? qrs.map((q, i) => `<button data-q="${i}" class="${i ? "" : "on"}">${esc(q.label)}</button>`).join("") : "";
        if (qrs.length > 1) $("qrcap").textContent = "Scan with a phone camera · " + qrs[0].caption;
      } }
    const q = s.question;
    if (q && q.id !== askId) { askId = q.id; $("askText").textContent = q.text; $("askPw").hidden = q.kind !== "password";
      $("askPw").value = ""; $("askYes").textContent = q.kind === "password" ? "Unlock" : "Yes";
      $("askNo").textContent = q.kind === "password" ? "Cancel" : "No"; $("ask").classList.add("on");
      if (q.kind === "password") setTimeout(() => $("askPw").focus(), 50); }
    if (!q && askId !== null) { askId = null; $("ask").classList.remove("on"); }
  } catch (e) { $("dlStatus").textContent = appMode ? "⚠️ Lost connection to Shardrip - close the app and open it again."
                                     : "⚠️ Lost connection to Shardrip - is the terminal window still open?"; }
  setTimeout(poll, 700);
}
$("links").onclick = e => { const b = e.target.closest("button[data-c]"); if (b) copy(b.dataset.c); };
$("qrsw").onclick = e => { const b = e.target.closest("button[data-q]"); if (!b) return; const q = shownQrs[+b.dataset.q];
  if (!q) return; $("qr").innerHTML = q.svg; $("qrcap").textContent = "Scan with a phone camera · " + q.caption;
  for (const x of $("qrsw").children) x.classList.toggle("on", x === b); };
api("/api/defaults").then(d => { $("folder").value = d.folder;
  if (d.app) { appMode = true; document.querySelector(".tab[data-t=send]").style.display = "none";  // the app is download-only (v1)
    console.log("SHARDRIP app page ready, secure=" + window.isSecureContext + " camera=" + !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)); }
}).catch(() => {});
// ---- QR scanner: live camera (needs localhost/https) or a photo; BarcodeDetector if the browser has it, else jsQR ----
let scanStream = null, scanTimer = null, scanBusy = false, detector = null;
try { if ("BarcodeDetector" in window) detector = new BarcodeDetector({formats: ["qr_code"]}); } catch (e) { detector = null; }
const scanCanvas = document.createElement("canvas"), scanCtx = scanCanvas.getContext("2d", {willReadFrequently: true});
async function decodeFrom(src, w, h){
  const scale = Math.min(1, 1000 / Math.max(w, h));
  scanCanvas.width = Math.round(w * scale); scanCanvas.height = Math.round(h * scale);
  scanCtx.drawImage(src, 0, 0, scanCanvas.width, scanCanvas.height);
  if (detector) { try { const r = await detector.detect(scanCanvas); if (r.length) return r[0].rawValue; } catch (e) {} }
  if (typeof jsQR === "function") {
    const img = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
    const r = jsQR(img.data, img.width, img.height, {inversionAttempts: "attemptBoth"});
    if (r && r.data) return r.data;
  }
  return null;
}
function stopScanner(){ clearInterval(scanTimer); scanTimer = null;
  if (scanStream) { scanStream.getTracks().forEach(t => t.stop()); scanStream = null; }
  $("scanVideo").srcObject = null; $("scanner").classList.remove("on"); }
function useScanned(text){
  stopScanner();
  if (!/^https?:\/\//i.test(text)) { toast("That QR isn't a download link"); return; }
  $("url").value = text.trim(); nameAuto = true; $("url").oninput();
  document.querySelector(".tab[data-t=dl]").click();
  if (/\.shardlock($|[?#])/i.test(text)) { $("dlpw").focus(); toast("🔒 Locked file - enter the password, then Start"); }
  else toast("Link filled ✓ - press Start download");
}
async function openScanner(){
  $("scanner").classList.add("on"); $("scanCam").hidden = false; $("scanHint").textContent = "Starting camera…";
  if (!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia && window.isSecureContext)) {
    $("scanCam").hidden = true;
    $("scanHint").textContent = "Live camera isn't available here. Tap “Upload QR image” and pick a screenshot or photo of the QR.";
    return;
  }
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({video: {facingMode: {ideal: "environment"}}, audio: false});
    const v = $("scanVideo"); v.srcObject = scanStream; await v.play();
    $("scanHint").textContent = "Point the camera at the QR code, or tap “Upload QR image” to use a screenshot.";
    scanTimer = setInterval(async () => {
      if (scanBusy || v.readyState < 2 || !v.videoWidth) return;
      scanBusy = true;
      try { const t = await decodeFrom(v, v.videoWidth, v.videoHeight); if (t) useScanned(t); } finally { scanBusy = false; }
    }, 250);
  } catch (e) {
    $("scanCam").hidden = true;
    $("scanHint").textContent = (e && e.name === "NotFoundError" ? "No camera found." : "Couldn't open the camera (" + (e.name || e) + ").") + " Tap “Upload QR image” and pick a screenshot or photo of the QR.";
  }
}
$("scanBtn").onclick = openScanner;
$("scanClose").onclick = stopScanner;
$("scanPhoto").onclick = () => $("scanFile").click();
$("scanFile").onchange = async () => {
  const f = $("scanFile").files[0]; $("scanFile").value = ""; if (!f) return;
  try { const bmp = await createImageBitmap(f); const t = await decodeFrom(bmp, bmp.width, bmp.height);
        if (t) useScanned(t); else toast("No QR code found in that image - try a clearer screenshot or photo"); }
  catch (e) { toast("Couldn't read that image"); }
};

poll();
</script></body></html>
"""


# ============================================================================
# Entry point
# ============================================================================

def main():
    ap = argparse.ArgumentParser(description=f"Shardrip {VERSION} - multi-connection downloader & file sender")
    ap.add_argument("urls", nargs="*", help="URL(s) of the SAME file; extra ones are mirrors. Omit for the menu.")
    ap.add_argument("-o", "--output", help="output file path")
    ap.add_argument("-c", "--connections", type=int, default=16, help="parallel connections (default 16)")
    ap.add_argument("--chunk-mb", type=int, default=16, help="chunk size in MB (default 16)")
    ap.add_argument("--sha256", help="expected SHA256 to verify at the end")
    ap.add_argument("--password", help="download: unlock a locked file / send: lock with this password")
    ap.add_argument("--overwrite", action="store_true", help="replace an existing output file without asking")
    ap.add_argument("--via", choices=list(VIA), default="auto",
                    help="smart links: auto = same network if the sender is on it, else internet (default); "
                         "lan = same network only; internet = internet link only")
    ap.add_argument("--serve", metavar="FILE", help="SEND mode: share FILE so someone else can download it")
    ap.add_argument("--lock", action="store_true", help="--serve with a generated password (encrypts the file)")
    ap.add_argument("--port", type=int, default=8080, help="port for --serve (default 8080)")
    ap.add_argument("--no-tunnel", action="store_true", help="--serve without the public Cloudflare link")
    ap.add_argument("--no-qr", action="store_true", help="--serve without printing the QR code")
    ap.add_argument("--gui", action="store_true", help="open the window version")
    ap.add_argument("--web", action="store_true", help="open the web interface in your browser (works on phones)")
    ap.add_argument("--app", action="store_true", help="open the full app in its own window (like Shardrip.exe)")
    ap.add_argument("--lan", action="store_true", help="--web: also allow other devices on your Wi-Fi to use it")
    ap.add_argument("--web-port", type=int, default=7777, help="port for --web (default 7777)")
    ap.add_argument("--no-browser", action="store_true", help="--web: don't open the browser automatically")
    ap.add_argument("--selftest", action="store_true", help="check that everything Shardrip needs is working")
    a = ap.parse_args()
    if a.selftest:
        res = self_test()
        print("\n".join(res))
        return all(r.startswith("PASS") for r in res)

    if a.app:
        app_main()
        return True
    if not a.urls and not a.serve and not a.gui and not a.web:
        a = interactive()
    if getattr(a, "web", False):
        web_main(a.web_port, getattr(a, "lan", False), not getattr(a, "no_browser", False))
        return True
    if getattr(a, "gui", False):
        if IS_ANDROID:
            print("The window version needs a desktop. On Android use:  python shardrip.py --web")
            return False
        gui_main()
        return True
    if a.serve:
        password = a.password or (gen_password() if a.lock else None)
        return cli_serve(a.serve, a.port, not a.no_tunnel, password, show_qr=not a.no_qr)
    return cli_download(a.urls, a.output, a.connections, a.chunk_mb, a.sha256, a.password, a.overwrite,
                        getattr(a, "via", "auto"))


if __name__ == "__main__":
    interactive_mode = len(sys.argv) == 1
    ok = False
    try:
        ok = main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        if interactive_mode and sys.stdin and sys.stdin.isatty():
            input("\nPress Enter to close...")
    sys.exit(0 if ok else 1)
