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

Usage:
  Interactive:  double-click shardrip.py (or run: python shardrip.py) and answer the prompts
  Command line: python shardrip.py URL [MIRROR2 ...] -o kali.iso -c 16 --sha256 <hash>

Resume: run it again with the same URL + save location; finished chunks are skipped.
"""
import argparse
import hashlib
import json
import os
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

try:
    import requests
except ImportError:  # first run on a fresh machine: install it automatically
    import subprocess
    print("Installing 'requests' (one-time)...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

READ_SIZE = 256 * 1024
UA = {"User-Agent": "shardrip/1.0"}
_local = threading.local()


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


def interactive():
    """Ask for everything instead of using command-line args."""
    print("=" * 56)
    print("  ⚡ SHARDRIP - multi-connection downloader")
    print("=" * 56)

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

    default_name = os.path.basename(url.split("?")[0]) or "download.bin"
    name = ask("File name", default_name)
    conns = ask("Connections (1-32)", 16, int, lambda n: 1 <= n <= 32)
    sha = input("  SHA256 to verify (Enter to skip): ").strip() or None
    if sha and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
        print("    ↳ That doesn't look like a SHA256 (64 hex chars) - skipping verification.")
        sha = None

    print()
    return argparse.Namespace(urls=[url] + mirrors, output=os.path.join(folder, name),
                              connections=conns, chunk_mb=16, sha256=sha)


def main():
    ap = argparse.ArgumentParser(description="Multi-connection, multi-mirror downloader")
    ap.add_argument("urls", nargs="*", help="URL(s) of the SAME file; extra ones are mirrors. Omit for interactive mode.")
    ap.add_argument("-o", "--output", help="output filename")
    ap.add_argument("-c", "--connections", type=int, default=16, help="parallel connections (default 16)")
    ap.add_argument("--chunk-mb", type=int, default=16, help="chunk size in MB (default 16)")
    ap.add_argument("--sha256", help="expected SHA256 to verify at the end")
    a = ap.parse_args()
    if not a.urls:
        a = interactive()

    out = a.output or os.path.basename(a.urls[0].split("?")[0]) or "download.bin"
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
