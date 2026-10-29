#!/usr/bin/env python3
"""
shardrip.py - DIY multi-connection, multi-mirror downloader (IDM/aria2 style).

How it works:
  1. Probe the file size + check the server supports HTTP Range requests.
  2. Split the file into chunks (default 16 MB).
  3. A pool of N worker threads pulls chunks off a queue, each requesting
     "Range: bytes=start-end" from a mirror (round-robin across mirrors).
  4. Each chunk is written straight into its byte offset in a pre-sized file.
  5. Finished chunks are recorded in <file>.state so you can resume.
  6. Optional SHA256 check at the end.

Send mode (--serve):
  Shares one file from your PC over a Range-capable HTTP server. By default it also
  opens a free Cloudflare Quick Tunnel, so you get a public https link that works over
  the internet with no port forwarding (works behind CGNAT too). The receiver downloads
  it with Shardrip using parallel connections, plus automatic SHA256 verification.

Usage:
  Interactive:  double-click shardrip.py (or run: python shardrip.py) and answer the prompts
  Download:     python shardrip.py URL [MIRROR2 ...] -o kali.iso -c 16 --sha256 <hash>
  Send:         python shardrip.py --serve "C:\\path\\to\\file.iso" [--port 8080] [--no-tunnel]

Resume: run it again with the same URL + save location; finished chunks are skipped.
"""
import argparse
import hashlib
import http.server
import json
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

try:
    import requests
except ImportError:  # first run on a fresh machine: install it automatically
    print("Installing 'requests' (one-time)...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

READ_SIZE = 256 * 1024
UA = {"User-Agent": "shardrip/1.2"}
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


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


class Progress:
    def __init__(self, total, already):
        self.total, self.done = total, already
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.start_done, self.t0 = already, time.time()

    def add(self, n):
        with self.lock:
            self.done += n

    def run(self):
        while not self.stop.wait(0.5):
            self.draw()
        self.draw()
        print()

    def draw(self):
        el = max(time.time() - self.t0, 1e-6)
        speed = (self.done - self.start_done) / el
        pct = self.done / self.total * 100 if self.total else 0
        eta = (self.total - self.done) / speed if speed > 0 else 0
        bar = "#" * int(pct / 4)
        sys.stdout.write(f"\r[{bar:<25}] {pct:5.1f}%  "
                         f"{human(self.done)}/{human(self.total)}  "
                         f"{human(speed)}/s  ETA {int(eta//60)}m{int(eta%60):02d}s ")
        sys.stdout.flush()


def fetch_chunk(urls, idx, start, end, path, prog, retries=6):
    """Download bytes [start, end] into path at offset start. Rotates mirrors on failure."""
    for attempt in range(retries):
        url = urls[(idx + attempt) % len(urls)]
        got = 0
        try:
            with session().get(url, headers={"Range": f"bytes={start}-{end}"},
                               stream=True, timeout=30) as r:
                if r.status_code != 206:
                    raise IOError(f"HTTP {r.status_code} (no range support?)")
                buf = bytearray()
                for block in r.iter_content(READ_SIZE):
                    buf += block
                    got += len(block)
                    prog.add(len(block))
            if len(buf) != end - start + 1:
                raise IOError(f"short read {len(buf)} != {end - start + 1}")
            with open(path, "r+b") as f:
                f.seek(start)
                f.write(buf)
            return idx
        except Exception as e:
            prog.add(-got)  # roll back progress for the failed attempt
            if attempt == retries - 1:
                raise RuntimeError(f"chunk {idx} failed: {e}")
            time.sleep(min(2 ** attempt, 15))


def single_stream(url, path, size):
    print("Server doesn't support ranges -> single connection download.")
    prog = Progress(size, 0)
    t = threading.Thread(target=prog.run, daemon=True)
    t.start()
    with session().get(url, stream=True, timeout=30) as r, open(path, "wb") as f:
        r.raise_for_status()
        for block in r.iter_content(READ_SIZE):
            f.write(block)
            prog.add(len(block))
    prog.stop.set()
    t.join()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


# ----------------------------------------------------------------------------
# Send mode: share a file over HTTP (with Range support) + optional public tunnel
# ----------------------------------------------------------------------------

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
        out = subprocess.run([exe, "ip", "-4"], capture_output=True, text=True, timeout=5)
        ip = out.stdout.strip().splitlines()[0] if out.returncode == 0 and out.stdout.strip() else None
        return ip
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


def find_cloudflared():
    """Find cloudflared on PATH or next to this script; download it from GitHub if missing."""
    here = os.path.dirname(os.path.abspath(__file__))
    is_win = platform.system() == "Windows"
    local = os.path.join(here, "cloudflared.exe" if is_win else "cloudflared")
    found = shutil.which("cloudflared") or (local if os.path.isfile(local) else None)
    if found:
        return found

    asset = CLOUDFLARED_ASSETS.get((platform.system(), platform.machine().lower()))
    if not asset:
        print("    ↳ No automatic cloudflared download for this OS. Install it from")
        print("      https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
        return None

    print("Downloading cloudflared (one-time, ~40 MB, official Cloudflare release from GitHub)...")
    try:
        with requests.get(CLOUDFLARED_BASE + asset, stream=True, timeout=60, headers=UA) as r:
            r.raise_for_status()
            tmp = local + ".part"
            with open(tmp, "wb") as f:
                for block in r.iter_content(READ_SIZE):
                    f.write(block)
        os.replace(tmp, local)
        if not is_win:
            os.chmod(local, 0o755)
        return local
    except Exception as e:
        print(f"    ↳ Couldn't download cloudflared: {e}")
        return None


def start_tunnel(port, timeout=60):
    """Start a Cloudflare Quick Tunnel to localhost:port. Returns (process, public_url) or (None, None)."""
    exe = find_cloudflared()
    if not exe:
        return None, None
    proc = subprocess.Popen(
        [exe, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        encoding="utf-8", errors="replace",
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
        self.t0 = time.time()
        self.last_sent, self.last_t = 0, time.time()

    def add(self, n):
        with self.lock:
            self.sent += n

    def conn(self, delta):
        with self.lock:
            self.active += delta

    def line(self):
        now = time.time()
        with self.lock:
            sent, active = self.sent, self.active
        speed = (sent - self.last_sent) / max(now - self.last_t, 1e-6)
        self.last_sent, self.last_t = sent, now
        return f"\r  Sent {human(sent)}  |  {human(speed)}/s  |  {active} active connection(s)  |  Ctrl+C to stop   "


def make_handler(file_path, url_path, size, name, stats):
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

            length = end - start + 1
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quoted_name}")
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if head:
                return

            stats.conn(+1)
            try:
                with open(file_path, "rb") as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        data = f.read(min(READ_SIZE, remaining))
                        if not data:
                            break
                        self.wfile.write(data)
                        remaining -= len(data)
                        stats.add(len(data))
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # receiver closed the connection (normal on cancel/retry)
            finally:
                stats.conn(-1)

    return Handler


def serve(file_path, port=8080, tunnel=True):
    file_path = os.path.abspath(file_path)
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    name = os.path.basename(file_path)
    size = os.path.getsize(file_path)

    print(f"File: {name}  ({human(size)})")
    print("Hashing (SHA256) so the receiver can verify the download...")
    digest = sha256_file(file_path)

    token = secrets.token_urlsafe(9)  # secret path: the link can't be guessed
    url_path = f"/{token}/{name}"
    link_path = f"/{token}/{urllib.parse.quote(name)}"

    stats = ServeStats()
    try:
        server = http.server.ThreadingHTTPServer(("0.0.0.0", port), make_handler(file_path, url_path, size, name, stats))
    except OSError as e:
        raise OSError(f"Port {port} is in use or blocked ({e}). Try a different port with --port.")
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    links = [("Same network (LAN)", f"http://{lan_ip()}:{port}{link_path}")]
    ts = tailscale_ip()
    if ts:
        links.append(("Tailscale", f"http://{ts}:{port}{link_path}"))

    tunnel_proc = None
    if tunnel:
        print("Opening a public Cloudflare tunnel (no port forwarding needed)...")
        tunnel_proc, public = start_tunnel(port)
        if public:
            links.insert(0, ("Internet (public link)", public + link_path))
        else:
            print("    ↳ Tunnel didn't start. LAN/Tailscale links still work.")

    print()
    print("=" * 64)
    print("  ⚡ SHARING - send the receiver one of these links:")
    print("=" * 64)
    for label, link in links:
        print(f"  {label}:\n    {link}")
    print(f"\n  SHA256: {digest}")
    print("\n  Receiver runs:")
    print(f'    python shardrip.py "{links[0][1]}" --sha256 {digest}')
    print("  (or opens the link in a browser - slower, single connection)")
    print("=" * 64)
    print("  Anyone with the link can download the file while this window is open.")
    print()

    try:
        while True:
            time.sleep(1)
            sys.stdout.write(stats.line())
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        if tunnel_proc:
            tunnel_proc.terminate()
        server.shutdown()
    print("Sharing stopped.")


# ----------------------------------------------------------------------------
# Interactive prompts
# ----------------------------------------------------------------------------

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


def pick_folder(default):
    """Open a Windows/Mac/Linux folder picker; fall back to the default if unavailable/cancelled."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = filedialog.askdirectory(initialdir=default, title="Choose where to save the download")
        root.destroy()
        return folder or default
    except Exception:
        print("    ↳ Folder picker unavailable, using default.")
        return default


def pick_file():
    """Open a file picker; returns '' if unavailable/cancelled."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askopenfilename(title="Choose a file to send")
        root.destroy()
        return path or ""
    except Exception:
        return ""


def url_filename(url):
    return urllib.parse.unquote(os.path.basename(url.split("?")[0])) or "download.bin"


def interactive():
    """Ask for everything instead of using command-line args."""
    print("=" * 56)
    print("  ⚡ SHARDRIP - multi-connection downloader")
    print("=" * 56)
    print("  1) Download a file")
    print("  2) Send a file to someone")
    mode = ask("Choose", "1", str, lambda v: v in ("1", "2"))

    if mode == "2":
        while True:
            path = ask("File to send (drag it in, or B = browse)")
            if path.lower() == "b":
                path = pick_file()
                print(f"    ↳ {path or '(cancelled)'}")
            if path and os.path.isfile(path):
                break
            print("    ↳ File not found, try again.")
        port = ask("Port", 8080, int, lambda n: 1024 <= n <= 65535)
        public = ask("Public internet link via Cloudflare? (Y/n)", "y", str,
                     lambda v: v.lower() in ("y", "n", "yes", "no"))
        print()
        return argparse.Namespace(serve=path, port=port, no_tunnel=public.lower().startswith("n"))

    url = ask("Download URL")
    mirrors = []
    while True:
        m = input("  Extra mirror URL (Enter to skip): ").strip().strip('"')
        if not m:
            break
        mirrors.append(m)

    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    folder = ask("Save folder (B = browse)", downloads)
    if folder.lower() == "b":
        folder = pick_folder(downloads)
        print(f"    ↳ {folder}")
    os.makedirs(folder, exist_ok=True)

    name = ask("File name", url_filename(url))
    conns = ask("Connections (1-32)", 16, int, lambda n: 1 <= n <= 32)
    sha = input("  SHA256 to verify (Enter to skip): ").strip() or None
    if sha and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
        print("    ↳ That doesn't look like a SHA256 (64 hex chars) - skipping verification.")
        sha = None

    print()
    return argparse.Namespace(urls=[url] + mirrors, output=os.path.join(folder, name),
                              connections=conns, chunk_mb=16, sha256=sha, serve=None)


def main():
    ap = argparse.ArgumentParser(description="Multi-connection, multi-mirror downloader")
    ap.add_argument("urls", nargs="*", help="URL(s) of the SAME file; extra ones are mirrors. Omit for interactive mode.")
    ap.add_argument("-o", "--output", help="output filename")
    ap.add_argument("-c", "--connections", type=int, default=16, help="parallel connections (default 16)")
    ap.add_argument("--chunk-mb", type=int, default=16, help="chunk size in MB (default 16)")
    ap.add_argument("--sha256", help="expected SHA256 to verify at the end")
    ap.add_argument("--overwrite", action="store_true", help="replace an existing output file without asking")
    ap.add_argument("--serve", metavar="FILE", help="SEND mode: share FILE so someone else can download it")
    ap.add_argument("--port", type=int, default=8080, help="port for --serve (default 8080)")
    ap.add_argument("--no-tunnel", action="store_true", help="--serve without the public Cloudflare link (LAN/Tailscale only)")
    a = ap.parse_args()
    if not a.urls and not a.serve:
        a = interactive()

    if a.serve:
        return serve(a.serve, a.port, tunnel=not a.no_tunnel)

    out = a.output or url_filename(a.urls[0])
    state_path = out + ".state"

    # Probe all mirrors, drop any that disagree on size or lack range support
    size, ranges = probe(a.urls[0])
    urls = [a.urls[0]]
    for u in a.urls[1:]:
        try:
            s, r = probe(u)
            if s == size and r:
                urls.append(u)
            else:
                print(f"Skipping mirror (size/range mismatch): {u}")
        except Exception as e:
            print(f"Skipping mirror ({e}): {u}")

    print(f"File: {out}  Size: {human(size)}  Mirrors: {len(urls)}  Connections: {a.connections}")

    # Never silently wipe a file that's already there (e.g. a finished download).
    # A .state file next to it means it's a resumable partial download, which is fine.
    if os.path.exists(out) and not os.path.exists(state_path) and not getattr(a, "overwrite", False):
        print(f"\n⚠️  {out} already exists ({human(os.path.getsize(out))}).")
        if a.sha256:
            print("Checking whether it's already complete...")
            if sha256_file(out).lower() == a.sha256.lower():
                print("It's already fully downloaded and the SHA256 matches ✅ - nothing to do.")
                return
            print("Its SHA256 doesn't match, so it's incomplete or a different file.")
        try:
            ans = input("Overwrite it? (y/N): ").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("Cancelled - existing file left untouched. (Use -o to save under another name.)")
            return

    if not ranges or size == 0:
        single_stream(urls[0], out, size)
    else:
        chunk = a.chunk_mb * 1024 * 1024
        chunks = [(i, s, min(s + chunk, size) - 1) for i, s in enumerate(range(0, size, chunk))]

        # Load resume state
        done = set()
        if os.path.exists(state_path) and os.path.exists(out):
            try:
                with open(state_path) as f:
                    st = json.load(f)
                if st.get("size") == size and st.get("chunk") == chunk:
                    done = set(st["done"])
                    print(f"Resuming: {len(done)}/{len(chunks)} chunks already done")
            except (ValueError, KeyError):
                print("State file unreadable, starting fresh.")
        if not done:
            with open(out, "wb") as f:
                f.truncate(size)  # pre-allocate

        already = sum(e - s + 1 for i, s, e in chunks if i in done)
        prog = Progress(size, already)
        pt = threading.Thread(target=prog.run, daemon=True)
        pt.start()

        state_lock = threading.Lock()
        todo = [c for c in chunks if c[0] not in done]
        failed = []
        pool = ThreadPoolExecutor(max_workers=a.connections)
        pending = {pool.submit(fetch_chunk, urls, i, s, e, out, prog) for i, s, e in todo}
        try:
            # Poll with a short timeout so Ctrl+C is caught (blocking waits ignore it on Windows)
            while pending:
                finished, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for fut in finished:
                    try:
                        idx = fut.result()
                        with state_lock:
                            done.add(idx)
                            tmp = state_path + ".tmp"
                            with open(tmp, "w") as f:
                                json.dump({"size": size, "chunk": chunk, "done": sorted(done)}, f)
                            os.replace(tmp, state_path)  # atomic: never a half-written state file
                    except Exception as e:
                        failed.append(str(e))
        except KeyboardInterrupt:
            prog.stop.set()
            print(f"\nStopped at {len(done)}/{len(chunks)} chunks. Re-run the same command to resume.")
            os._exit(1)  # kill worker threads immediately
        pool.shutdown()
        prog.stop.set()
        pt.join()

        if failed:
            print(f"{len(failed)} chunk(s) failed. Re-run the same command to retry them.")
            sys.exit(1)
        os.remove(state_path)

    print(f"Done: {out}")
    if a.sha256:
        print("Verifying SHA256...")
        got = sha256_file(out)
        if got.lower() == a.sha256.lower():
            print("SHA256 OK ✅")
        else:
            print(f"SHA256 MISMATCH ❌\n expected {a.sha256}\n got      {got}")
            sys.exit(2)


if __name__ == "__main__":
    interactive_mode = len(sys.argv) == 1
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if not interactive_mode:
            sys.exit(1)
    finally:
        if interactive_mode:  # keep a double-clicked window open so you can read the result
            input("\nPress Enter to close...")
