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
"""
import argparse
import getpass
import hashlib
import http.server
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

VERSION = "2.1"
IS_WIN = platform.system() == "Windows"
IS_ANDROID = "ANDROID_ROOT" in os.environ or "TERMUX_VERSION" in os.environ or sys.platform == "android"
NO_WINDOW = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW: no console pop-ups from the GUI

# Packages that pip can't build on Android - Termux ships them ready-made instead.
TERMUX_PKGS = {"cryptography": "python-cryptography"}


def default_download_dir():
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

def fetch_chunk(urls, idx, start, end, path, prog, stop, retries=6):
    """Download bytes [start, end] into path at offset start. Rotates mirrors on failure."""
    for attempt in range(retries):
        if stop.is_set():
            raise Stopped()
        url = urls[(idx + attempt) % len(urls)]
        got = 0
        try:
            with session().get(url, headers={"Range": f"bytes={start}-{end}"},
                               stream=True, timeout=30) as r:
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


def download(urls, out, ui, connections=16, chunk_mb=16, sha256=None, password=None,
             overwrite=False, stop=None):
    """Download urls -> out. Returns the final file path, or None if cancelled/failed."""
    stop = stop or threading.Event()
    out = os.path.abspath(out)
    state_path = out + ".state"
    os.makedirs(os.path.dirname(out), exist_ok=True)

    size, ranges = probe(urls[0])
    good = [urls[0]]
    for u in urls[1:]:
        try:
            s, r = probe(u)
            if s == size and r:
                good.append(u)
            else:
                ui.log(f"Skipping mirror (size/range mismatch): {u}")
        except Exception as e:
            ui.log(f"Skipping mirror ({e}): {u}")
    urls = good
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
        pending = {pool.submit(fetch_chunk, urls, i, s, e, out, prog, stop) for i, s, e in todo}
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

    def drain():
        # Keep reading forever: if the pipe fills up, cloudflared would stall.
        sent = False
        for line in proc.stdout:
            if not sent:
                m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
                if m:
                    found.put(m.group(0))
                    sent = True
        if not sent:
            found.put(None)

    threading.Thread(target=drain, daemon=True).start()
    try:
        url = found.get(timeout=timeout)
    except queue.Empty:
        url = None
    if not url:
        proc.terminate()
        return None, None
    return proc, url


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

        self.links = [("Same network (LAN)", f"http://{lan_ip()}:{self.port}{link_path}")]
        ts = tailscale_ip()
        if ts:
            self.links.append(("Tailscale", f"http://{ts}:{self.port}{link_path}"))
        if self.tunnel:
            if stop is not None and stop.is_set():
                raise Stopped()
            self.ui.log("Opening a public Cloudflare tunnel (no port forwarding needed)...")
            self.tunnel_proc, public = start_tunnel(self.port, self.ui)
            if public:
                self.links.insert(0, ("Internet (public link)", public + link_path))
            else:
                self.ui.log("Tunnel didn't start. LAN/Tailscale links still work.")
        return self

    @property
    def main_link(self):
        return self.links[0][1] if self.links else ""

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


def cli_download(urls, output, connections, chunk_mb, sha256, password, overwrite):
    ui = ConsoleUI()
    out = output or url_filename(urls[0])
    try:
        return download(urls, out, ui, connections, chunk_mb, sha256, password, overwrite) is not None
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
    print("  3) Open the window (GUI)" + ("  [not available on Android]" if IS_ANDROID else ""))
    print("  4) Open in your web browser (works on phones too)")
    mode = ask("Choose", "1", str, lambda v: v in ("1", "2", "3", "4"))

    if mode == "3":
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

def gui_main(_test_hook=None):
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from tkinter.scrolledtext import ScrolledText

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
            return self.app.call_main(lambda: messagebox.askyesno("Shardrip", question, parent=self.app.root))

        def ask_password(self):
            return self.app.call_main(lambda: simpledialog.askstring(
                "Password needed", "This file is password-locked.\nEnter the password:",
                show="•", parent=self.app.root))

        def start_progress(self, total, already=0, label=""):
            p = Progress(total, already, label)
            self.app.q.put(("progress", self.tab, p))
            return p

    class App:
        def __init__(self, root):
            self.root = root
            self.q = queue.Queue()
            self.prog = {"dl": None, "send": None}
            self.dl_stop = None
            self._row_vars = []
            self.share = None
            self.send_stop = None
            root.title(f"Shardrip {VERSION}")
            root.geometry("780x760")
            root.minsize(680, 640)
            style = ttk.Style()
            if "vista" not in style.theme_names():
                style.theme_use("clam")
            style.configure("Big.TButton", padding=(14, 6))
            style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
            style.configure("Muted.TLabel", foreground="#666666")
            style.configure("Shard.Horizontal.TProgressbar", background="#2e9d4f", troughcolor="#e6e6e6",
                            thickness=16)

            head = ttk.Frame(root, padding=(14, 10, 14, 0))
            head.pack(fill="x")
            ttk.Label(head, text="⚡ Shardrip", style="Title.TLabel").pack(side="left")
            ttk.Label(head, text="  multi-connection downloader & file sender",
                      style="Muted.TLabel").pack(side="left", pady=(6, 0))

            nb = ttk.Notebook(root)
            nb.pack(fill="both", expand=True, padx=12, pady=10)
            self.dl_tab = ttk.Frame(nb, padding=12)
            self.send_tab = ttk.Frame(nb, padding=12)
            nb.add(self.dl_tab, text="  ⬇  Download  ")
            nb.add(self.send_tab, text="  ⬆  Send  ")
            self.nb = nb
            self.build_download()
            self.build_send()
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

        @staticmethod
        def log_to(widget, msg):
            widget.configure(state="normal")
            widget.insert("end", msg + "\n")
            widget.see("end")
            widget.configure(state="disabled")

        def row(self, parent, r, label, widget, extra=None):
            ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", pady=4, padx=(0, 10))
            widget.grid(row=r, column=1, sticky="ew", pady=4)
            if extra is not None:
                extra.grid(row=r, column=2, sticky="w", padx=(8, 0), pady=4)

        # ---------- download tab ----------
        def build_download(self):
            f = self.dl_tab
            form = ttk.Frame(f)
            form.pack(fill="x")
            form.columnconfigure(1, weight=1)

            self.url = tk.StringVar()
            self.mirrors = tk.StringVar()
            self.folder = tk.StringVar(value=default_download_dir())
            self.fname = tk.StringVar()
            self.conns = tk.IntVar(value=16)
            self.sha = tk.StringVar()
            self.dl_pw = tk.StringVar()
            self._name_auto = True

            self.row(form, 0, "Download URL", ttk.Entry(form, textvariable=self.url))
            self.row(form, 1, "Extra mirrors", ttk.Entry(form, textvariable=self.mirrors))
            ttk.Label(form, text="optional, separate with spaces", style="Muted.TLabel").grid(
                row=2, column=1, sticky="w")
            self.row(form, 3, "Save to", ttk.Entry(form, textvariable=self.folder),
                     ttk.Button(form, text="Browse…", command=self.pick_folder))
            name_entry = ttk.Entry(form, textvariable=self.fname)
            name_entry.bind("<Key>", lambda e: setattr(self, "_name_auto", False))
            self.row(form, 4, "File name", name_entry)
            self.row(form, 5, "Connections",
                     ttk.Spinbox(form, from_=1, to=32, textvariable=self.conns, width=6))
            self.row(form, 6, "SHA256 (optional)", ttk.Entry(form, textvariable=self.sha))
            self.row(form, 7, "Password (locked files)", ttk.Entry(form, textvariable=self.dl_pw, show="•"))
            self.url.trace_add("write", self.url_changed)

            btns = ttk.Frame(f)
            btns.pack(fill="x", pady=(10, 6))
            self.dl_start = ttk.Button(btns, text="⬇  Start download", style="Big.TButton",
                                       command=self.start_download)
            self.dl_start.pack(side="left")
            self.dl_stopbtn = ttk.Button(btns, text="■  Stop", style="Big.TButton",
                                         command=self.stop_download, state="disabled")
            self.dl_stopbtn.pack(side="left", padx=8)

            self.dl_bar = ttk.Progressbar(f, maximum=100, style="Shard.Horizontal.TProgressbar")
            self.dl_bar.pack(fill="x", pady=(6, 2))
            self.dl_info = ttk.Label(f, text="Ready.")
            self.dl_info.pack(anchor="w")
            self.dl_log = ScrolledText(f, height=12, state="disabled", font=("Consolas", 9), wrap="word")
            self.dl_log.pack(fill="both", expand=True, pady=(8, 0))

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
                messagebox.showwarning("Shardrip", "Paste a direct http(s) download link first.", parent=self.root)
                return
            urls = [url] + [m for m in self.mirrors.get().split() if m]
            out = os.path.join(self.folder.get().strip(), self.fname.get().strip() or url_filename(url))
            sha = self.sha.get().strip() or None
            if sha and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
                messagebox.showwarning("Shardrip", "That SHA256 doesn't look right (64 hex characters).",
                                       parent=self.root)
                return
            try:
                conns = max(1, min(32, int(self.conns.get())))
            except (tk.TclError, ValueError):
                conns = 16
            pw = self.dl_pw.get() or None
            self.dl_stop = threading.Event()
            self.dl_start.configure(state="disabled")
            self.dl_stopbtn.configure(state="normal")
            self.dl_bar["value"] = 0
            self.dl_info.configure(text="Starting…")
            ui = GuiUI(self, "dl")

            def work():
                try:
                    res = download(urls, out, ui, conns, 16, sha, pw, False, self.dl_stop)
                except Exception as e:
                    ui.log(f"❌ Error: {e}")
                    res = None
                self.q.put(("dl_done", res))

            threading.Thread(target=work, daemon=True).start()

        def stop_download(self):
            if self.dl_stop:
                self.dl_stop.set()
                self.dl_info.configure(text="Stopping…")

        # ---------- send tab ----------
        def build_send(self):
            f = self.send_tab
            form = ttk.Frame(f)
            form.pack(fill="x")
            form.columnconfigure(1, weight=1)
            self.send_path = tk.StringVar()
            self.port = tk.IntVar(value=8080)
            self.public = tk.BooleanVar(value=True)
            self.lock = tk.BooleanVar(value=False)
            self.send_pw = tk.StringVar()

            self.row(form, 0, "File to send", ttk.Entry(form, textvariable=self.send_path),
                     ttk.Button(form, text="Browse…", command=self.pick_file))
            opts = ttk.Frame(form)
            ttk.Label(opts, text="Port").pack(side="left")
            ttk.Spinbox(opts, from_=1024, to=65535, textvariable=self.port, width=7).pack(side="left", padx=(6, 18))
            ttk.Checkbutton(opts, text="Public internet link (Cloudflare)", variable=self.public).pack(side="left")
            self.row(form, 1, "Options", opts)
            lockf = ttk.Frame(form)
            ttk.Checkbutton(lockf, text="Lock with password", variable=self.lock,
                            command=self.lock_toggled).pack(side="left")
            self.pw_entry = ttk.Entry(lockf, textvariable=self.send_pw, width=26, state="disabled")
            self.pw_entry.pack(side="left", padx=8)
            self.gen_btn = ttk.Button(lockf, text="Generate", command=lambda: self.send_pw.set(gen_password()),
                                      state="disabled")
            self.gen_btn.pack(side="left")
            self.row(form, 2, "Security", lockf)

            btns = ttk.Frame(f)
            btns.pack(fill="x", pady=(10, 6))
            self.send_start = ttk.Button(btns, text="⬆  Start sharing", style="Big.TButton",
                                         command=self.start_share)
            self.send_start.pack(side="left")
            self.send_stopbtn = ttk.Button(btns, text="■  Stop sharing", style="Big.TButton",
                                           command=self.stop_share, state="disabled")
            self.send_stopbtn.pack(side="left", padx=8)
            self.send_info = ttk.Label(f, text="Pick a file and press Start sharing.")
            self.send_info.pack(anchor="w", pady=(4, 6))

            mid = ttk.Frame(f)
            mid.pack(fill="both", expand=True)
            self.links_frame = ttk.Frame(mid)
            self.links_frame.pack(side="left", fill="both", expand=True)
            self.links_frame.columnconfigure(0, weight=1)
            qrbox = ttk.Frame(mid)
            qrbox.pack(side="right", padx=(12, 0), anchor="n")
            self.qr = tk.Canvas(qrbox, width=220, height=220, bg="white", highlightthickness=1,
                                highlightbackground="#cccccc")
            self.qr.pack()
            self.qr_label = ttk.Label(qrbox, text="QR code appears here", style="Muted.TLabel")
            self.qr_label.pack(pady=(4, 0))

            self.send_log = ScrolledText(f, height=7, state="disabled", font=("Consolas", 9), wrap="word")
            self.send_log.pack(fill="both", expand=False, pady=(8, 0))

        def lock_toggled(self):
            on = self.lock.get()
            self.pw_entry.configure(state="normal" if on else "disabled")
            self.gen_btn.configure(state="normal" if on else "disabled")
            if on and not self.send_pw.get():
                self.send_pw.set(gen_password())

        def pick_file(self):
            p = filedialog.askopenfilename(parent=self.root, title="Choose a file to send")
            if p:
                self.send_path.set(p)

        def clear_links(self):
            for w in self.links_frame.winfo_children():
                w.destroy()
            self._row_vars = []
            self.qr.delete("all")
            self.qr_label.configure(text="QR code appears here")

        def add_copy_row(self, r, label, value, bold=False):
            ttk.Label(self.links_frame, text=label, font=("Segoe UI", 9, "bold") if bold else None).grid(
                row=r * 2, column=0, sticky="w", pady=(6, 0))
            row = ttk.Frame(self.links_frame)
            row.grid(row=r * 2 + 1, column=0, sticky="ew")
            row.columnconfigure(0, weight=1)
            var = tk.StringVar(value=value)
            self._row_vars.append(var)  # keep a reference, or Tk blanks the box
            ttk.Entry(row, textvariable=var, state="readonly").grid(row=0, column=0, sticky="ew")
            ttk.Button(row, text="Copy", width=6, command=lambda: self.copy(value)).grid(row=0, column=1, padx=(6, 0))

        def draw_qr(self, text):
            self.qr.delete("all")
            try:
                m = qr_encode(text)
            except Exception as e:
                self.qr_label.configure(text=f"QR unavailable: {e}")
                return
            n = len(m)
            quiet = 3
            px = max(1, 220 // (n + quiet * 2))
            off = (220 - px * n) // 2
            for y in range(n):
                for x in range(n):
                    if m[y][x]:
                        self.qr.create_rectangle(off + x * px, off + y * px, off + (x + 1) * px,
                                                 off + (y + 1) * px, fill="black", width=0)
            self.qr_label.configure(text="Scan with a phone camera")

        def start_share(self):
            path = self.send_path.get().strip().strip('"')
            if not os.path.isfile(path):
                messagebox.showwarning("Shardrip", "Pick a file to send first.", parent=self.root)
                return
            pw = self.send_pw.get().strip() if self.lock.get() else None
            if self.lock.get() and not pw:
                messagebox.showwarning("Shardrip", "Enter or generate a password for the lock.", parent=self.root)
                return
            try:
                port = int(self.port.get())
            except (tk.TclError, ValueError):
                port = 8080
            self.clear_links()
            self.send_start.configure(state="disabled")
            self.send_stopbtn.configure(state="normal")
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
            r = 0
            for label, link in share.links:
                self.add_copy_row(r, label, link, bold=(r == 0))
                r += 1
            self.add_copy_row(r, "Receiver runs", share.receiver_cmd)
            r += 1
            if share.password:
                self.add_copy_row(r, "🔒 Password - send it separately from the link", share.password, bold=True)
                r += 1
            elif share.sha256:
                self.add_copy_row(r, "SHA256", share.sha256)
                r += 1
            self.draw_qr(share.main_link)
            note = "Anyone with the link can download while sharing is on."
            if share.password:
                note += " Locked: receivers need Shardrip + the password."
            self.send_info.configure(text=note)
            self.log_to(self.send_log, "Sharing is live ✅")

        def stop_share(self):
            if self.send_stop:
                self.send_stop.set()
            share, self.share = self.share, None
            if share:
                threading.Thread(target=share.stop, daemon=True).start()
                self.log_to(self.send_log, "Sharing stopped.")
            self.send_start.configure(state="normal")
            self.send_stopbtn.configure(state="disabled")
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
                        self.dl_start.configure(state="normal")
                        self.dl_stopbtn.configure(state="disabled")
                        p = self.prog["dl"]
                        if p:
                            self.update_dl(p)
                        self.prog["dl"] = None
                        if item[1]:
                            self.dl_bar["value"] = 100
                            self.dl_info.configure(text=f"✅ Done: {item[1]}")
                        else:
                            self.dl_info.configure(text="Stopped / not completed - see log.")
                    elif kind == "shared":
                        self.show_share(item[1])
                    elif kind == "share_failed":
                        self.send_start.configure(state="normal")
                        self.send_stopbtn.configure(state="disabled")
                        self.send_info.configure(text="Not sharing - see log.")
            except queue.Empty:
                pass
            p = self.prog["dl"]
            if p:
                self.update_dl(p)
            if self.share:
                sent, speed, active = self.share.stats.sample()
                self.send_info.configure(
                    text=f"Sharing ✅   Sent {human(sent)}   |   {human(speed)}/s ({speed * 8 / 1e6:.0f} Mbps)"
                         f"   |   {active} active connection(s)")
            self.root.after(250 if self.share else 100, self.poll)

        def update_dl(self, p):
            done, total, speed, eta, pct = p.snapshot()
            self.dl_bar["value"] = pct
            pre = f"{p.label}: " if p.label else ""
            self.dl_info.configure(
                text=f"{pre}{pct:.1f}%   ·   {human(done)} / {human(total)}   ·   "
                     f"{human(speed)}/s ({speed * 8 / 1e6:.0f} Mbps)   ·   ETA {fmt_eta(eta)}")

        def on_close(self):
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
                             "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
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
                return self.send_body(200, WEB_PAGE.replace("__VERSION__", VERSION), "text/html; charset=utf-8")
            if not u.path.startswith("/api/") or not self.key_ok(self.headers.get("X-Shardrip-Key")):
                return self.json({"error": "forbidden"}, 403)
            try:
                if u.path == "/api/status":
                    return self.json(self.status())
                if u.path == "/api/defaults":
                    return self.json({"folder": default_download_dir(), "home": os.path.expanduser("~"),
                                      "android": IS_ANDROID, "windows": IS_WIN})
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
            state.dl_stop = stop = threading.Event()
            tab.running, tab.result, tab.progress, tab.status = True, None, None, "Starting…"
            ui = WebUI(state, "dl", stop)

            def work():
                try:
                    tab.result = download(urls, os.path.join(folder, name), ui, conns, 16, sha, pw, False, stop)
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


def web_main(port=7777, lan=False, open_it=True):
    key = secrets.token_urlsafe(16)
    allowed = {"localhost", "127.0.0.1", "[::1]"}
    ip = lan_ip()
    if lan:
        allowed.add(ip)
    state = WebState()
    try:
        server = QuietServer(("0.0.0.0" if lan else "127.0.0.1", port), make_web_handler(state, key, allowed))
    except OSError as e:
        raise OSError(f"Port {port} is in use ({e}). Try --web-port 7778")
    threading.Thread(target=server.serve_forever, daemon=True).start()

    local = f"http://127.0.0.1:{port}/?key={key}"
    print("=" * 64)
    print(f"  ⚡ SHARDRIP {VERSION} - web interface is running")
    print("=" * 64)
    print(f"  Open this in your browser:\n    {local}")
    if lan:
        lan_link = f"http://{ip}:{port}/?key={key}"
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
        if state.share:
            state.share.stop()
        if state.dl_stop:
            state.dl_stop.set()
        server.shutdown()
    os._exit(0)


WEB_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Shardrip</title>
<style>
:root{--bg:#f4f5f7;--card:#fff;--fg:#16181d;--muted:#667085;--line:#e2e5ea;--accent:#2e9d4f;--accent2:#24813f;
--danger:#c0392b;--input:#fff;--log:#f7f8fa;--shadow:0 1px 3px rgba(0,0,0,.08)}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e8eaed;--muted:#9aa3af;--line:#2a2f3a;
--input:#11141a;--log:#0c0e12;--shadow:none}}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:baseline;gap:10px;padding:16px 16px 6px;max-width:860px;margin:auto}
header h1{margin:0;font-size:22px}header span{color:var(--muted);font-size:13px}
main{max-width:860px;margin:auto;padding:0 16px 40px}
.tabs{display:flex;gap:6px;margin:8px 0 12px}
.tab{flex:1;padding:11px;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:10px;
font-weight:600;font-size:15px;cursor:pointer}
.tab.on{background:var(--accent);border-color:var(--accent);color:#fff}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:var(--shadow)}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 4px}
input[type=text],input[type=password],input[type=number]{width:100%;padding:11px 12px;border:1px solid var(--line);
border-radius:9px;background:var(--input);color:var(--fg);font-size:15px;min-width:0}
.row{display:flex;gap:8px;align-items:center}.row>input{flex:1}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
button{padding:11px 16px;border-radius:9px;border:1px solid var(--line);background:var(--card);color:var(--fg);
font-size:15px;cursor:pointer;white-space:nowrap}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
button.primary:hover{background:var(--accent2)}button.stop{color:var(--danger)}
button:disabled{opacity:.45;cursor:default}
.actions{display:flex;gap:8px;margin-top:16px}.actions button{flex:1}
.check{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:15px;color:var(--fg)}
.check input{width:20px;height:20px;accent-color:var(--accent)}
.bar{height:14px;background:var(--line);border-radius:7px;overflow:hidden;margin-top:16px}
.bar>div{height:100%;width:0;background:var(--accent);transition:width .4s}
.status{margin-top:8px;font-size:14px;color:var(--muted);word-break:break-word}
pre.log{background:var(--log);border:1px solid var(--line);border-radius:9px;padding:10px;margin:14px 0 0;
max-height:220px;overflow:auto;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.links{margin-top:14px;display:grid;gap:10px}
.lnk .t{font-size:13px;color:var(--muted);margin-bottom:4px}.lnk .t b{color:var(--fg)}
.share{display:grid;grid-template-columns:1fr 210px;gap:16px;align-items:start}
.qr{background:#fff;border-radius:10px;padding:6px;border:1px solid var(--line)}.qr svg{display:block;width:100%}
.qrcap{text-align:center;font-size:12px;color:var(--muted);margin-top:4px}
.pw{font:600 16px ui-monospace,Consolas,monospace}
.hint{font-size:13px;color:var(--muted);margin-top:6px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:flex-end;justify-content:center;z-index:9}
.modal.on{display:flex}.sheet{background:var(--card);width:100%;max-width:560px;border-radius:16px 16px 0 0;
padding:16px;max-height:85vh;display:flex;flex-direction:column}
@media (min-width:640px){.modal{align-items:center}.sheet{border-radius:16px}}
.sheet h3{margin:0 0 8px;font-size:17px}.crumb{font-size:12px;color:var(--muted);word-break:break-all;margin-bottom:8px}
.list{overflow:auto;border:1px solid var(--line);border-radius:9px;flex:1;min-height:160px}
.item{display:flex;justify-content:space-between;gap:8px;padding:12px;border-bottom:1px solid var(--line);cursor:pointer}
.item:last-child{border-bottom:0}.item:hover{background:var(--log)}.item small{color:var(--muted);white-space:nowrap}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:#16181d;color:#fff;padding:9px 16px;
border-radius:20px;font-size:14px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:10}.toast.on{opacity:1}
@media (max-width:640px){.share{grid-template-columns:1fr}.qr{max-width:240px;margin:auto}.grid2{grid-template-columns:1fr}
header{padding-top:12px}}
</style></head><body>
<header><h1>⚡ Shardrip</h1><span>v__VERSION__ · downloader &amp; file sender</span></header>
<main>
<div class="tabs"><button class="tab on" data-t="dl">⬇ Download</button><button class="tab" data-t="send">⬆ Send</button></div>

<section id="dl" class="card">
  <label>Download URL</label><input type="text" id="url" placeholder="https://… direct file link" autocomplete="off">
  <label>Save to</label><div class="row"><input type="text" id="folder"><button id="pickFolder">Browse</button></div>
  <label>File name</label><input type="text" id="name" autocomplete="off">
  <div class="grid2">
    <div><label>Connections</label><input type="number" id="conns" min="1" max="32" value="16"></div>
    <div><label>Password (locked files)</label><input type="password" id="dlpw" autocomplete="off"></div>
  </div>
  <label>Extra mirrors (optional, separate with spaces)</label><input type="text" id="mirrors" autocomplete="off">
  <label>SHA256 (optional)</label><input type="text" id="sha" autocomplete="off">
  <div class="actions"><button class="primary" id="dlStart">⬇ Start download</button><button class="stop" id="dlStop" disabled>■ Stop</button></div>
  <div class="bar"><div id="dlBar"></div></div>
  <div class="status" id="dlStatus">Ready.</div>
  <pre class="log" id="dlLog"></pre>
</section>

<section id="send" class="card" hidden>
  <label>File to send</label><div class="row"><input type="text" id="path"><button id="pickFile">Browse</button></div>
  <div class="grid2">
    <div><label>Port</label><input type="number" id="port" value="8080" min="1024" max="65535"></div>
    <div><label class="check"><input type="checkbox" id="public" checked> Public internet link</label></div>
  </div>
  <label class="check"><input type="checkbox" id="lock"> 🔒 Lock with password</label>
  <div class="row" id="pwrow" hidden style="margin-top:8px"><input type="text" id="sendpw" autocomplete="off"><button id="gen">Generate</button></div>
  <div class="actions"><button class="primary" id="sendStart">⬆ Start sharing</button><button class="stop" id="sendStop" disabled>■ Stop sharing</button></div>
  <div class="status" id="sendStatus">Pick a file and press Start sharing.</div>
  <div class="share" id="shareBox" hidden><div class="links" id="links"></div>
    <div><div class="qr" id="qr"></div><div class="qrcap">Scan with a phone camera</div></div></div>
  <pre class="log" id="sendLog"></pre>
</section>
</main>

<div class="modal" id="browser"><div class="sheet"><h3 id="bTitle">Choose</h3><div class="crumb" id="bPath"></div>
  <div class="list" id="bList"></div>
  <div class="actions"><button id="bUp">⬆ Up</button><button class="primary" id="bUse">Use this folder</button><button id="bClose">Cancel</button></div></div></div>
<div class="modal" id="ask"><div class="sheet"><h3>Shardrip</h3><p id="askText"></p>
  <input type="password" id="askPw" hidden autocomplete="off">
  <div class="actions"><button class="primary" id="askYes">OK</button><button id="askNo">Cancel</button></div></div></div>
<div class="toast" id="toast"></div>

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
$("dlStart").onclick = async () => {
  try { await api("/api/download", {url: $("url").value, folder: $("folder").value, name: $("name").value,
          connections: +$("conns").value, password: $("dlpw").value, mirrors: $("mirrors").value, sha256: $("sha").value});
        $("dlBar").style.width = "0"; }
  catch (e) { toast(e.message); }
};
$("dlStop").onclick = () => api("/api/download/stop", {}).catch(e => toast(e.message));

// ---- send ----
$("lock").onchange = () => { $("pwrow").hidden = !$("lock").checked; if ($("lock").checked && !$("sendpw").value) gen(); };
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
let shownShare = null;
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
        $("qr").innerHTML = sh.qr;
      } }
    const q = s.question;
    if (q && q.id !== askId) { askId = q.id; $("askText").textContent = q.text; $("askPw").hidden = q.kind !== "password";
      $("askPw").value = ""; $("askYes").textContent = q.kind === "password" ? "Unlock" : "Yes";
      $("askNo").textContent = q.kind === "password" ? "Cancel" : "No"; $("ask").classList.add("on");
      if (q.kind === "password") setTimeout(() => $("askPw").focus(), 50); }
    if (!q && askId !== null) { askId = null; $("ask").classList.remove("on"); }
  } catch (e) { $("dlStatus").textContent = "⚠️ Lost connection to Shardrip - is the terminal window still open?"; }
  setTimeout(poll, 700);
}
$("links").onclick = e => { const b = e.target.closest("button[data-c]"); if (b) copy(b.dataset.c); };
api("/api/defaults").then(d => { $("folder").value = d.folder; }).catch(() => {});
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
    ap.add_argument("--serve", metavar="FILE", help="SEND mode: share FILE so someone else can download it")
    ap.add_argument("--lock", action="store_true", help="--serve with a generated password (encrypts the file)")
    ap.add_argument("--port", type=int, default=8080, help="port for --serve (default 8080)")
    ap.add_argument("--no-tunnel", action="store_true", help="--serve without the public Cloudflare link")
    ap.add_argument("--no-qr", action="store_true", help="--serve without printing the QR code")
    ap.add_argument("--gui", action="store_true", help="open the window version")
    ap.add_argument("--web", action="store_true", help="open the web interface in your browser (works on phones)")
    ap.add_argument("--lan", action="store_true", help="--web: also allow other devices on your Wi-Fi to use it")
    ap.add_argument("--web-port", type=int, default=7777, help="port for --web (default 7777)")
    ap.add_argument("--no-browser", action="store_true", help="--web: don't open the browser automatically")
    ap.add_argument("--selftest", action="store_true", help="check that everything Shardrip needs is working")
    a = ap.parse_args()
    if a.selftest:
        res = self_test()
        print("\n".join(res))
        return all(r.startswith("PASS") for r in res)

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
    return cli_download(a.urls, a.output, a.connections, a.chunk_mb, a.sha256, a.password, a.overwrite)


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
