# ⚡ Shardrip

A free, open-source **multi-connection downloader** in a single Python file. It splits big files into chunks, downloads them in parallel (optionally from several mirrors), resumes after interruptions, and verifies the result with SHA256.

It does the same job as paid "download accelerators", with no ads, no installer and no account.

```
[##############           ]  58.8%  2.76 GB/4.70 GB  11.84 MB/s  ETA 2m43s
```

## Features

- **Parallel connections:** up to 32 simultaneous HTTP Range requests
- **Multiple mirrors:** spread chunks across several servers hosting the same file
- **Resume:** stop at any time (Ctrl+C, crash, power cut) and run it again to continue
- **SHA256 verification:** confirms the download isn't corrupted or tampered with
- **Interactive mode:** double-click and answer the prompts, no command line needed
- **Auto-fallback:** servers without Range support are downloaded over a single connection
- **One file:** the only dependency is `requests`, which installs itself on first run

## Quick start

**Requirements:** Python 3.8+

### Interactive (easiest)

Double-click `shardrip.py`, or run:

```bash
python shardrip.py
```

```
========================================================
  ⚡ SHARDRIP - multi-connection downloader
========================================================
  Download URL: https://example.com/big-file.iso
  Extra mirror URL (Enter to skip):
  Save folder (B = browse) [C:\Users\you\Downloads]:
  File name [big-file.iso]:
  Connections (1-32) [16]:
  SHA256 to verify (Enter to skip):
```

Press **Enter** to accept a default. Type **B** at the folder prompt to open a folder picker.

### Command line

```bash
python shardrip.py URL [MIRROR2 MIRROR3 ...] -o FILE -c 16 --sha256 HASH
```

| Option | Description | Default |
|---|---|---|
| `URL` | File to download. Extra URLs are treated as mirrors of the same file | required |
| `-o`, `--output` | Output file path | name taken from the URL |
| `-c`, `--connections` | Parallel connections | 16 |
| `--chunk-mb` | Chunk size in MB | 16 |
| `--sha256` | Expected SHA256 hash to verify at the end | none |

**Example: Kali Linux ISO**

```bash
python shardrip.py "https://cdimage.kali.org/kali-2026.3/kali-linux-2026.3-installer-amd64.iso" \
  -o kali.iso -c 16 \
  --sha256 db9cbed33edb45727d16911813c2434fcd1419585007884153be22a03b30ec2f
```

## How it works

1. **Probe:** asks the server for the file size and checks it supports HTTP Range requests.
2. **Split:** divides the file into fixed-size chunks (16 MB by default).
3. **Download:** a pool of worker threads requests `Range: bytes=start-end` for each chunk, rotating across mirrors. Failed chunks retry with backoff and switch to another mirror.
4. **Write:** each chunk is written directly to its position in a pre-allocated file, so no merge step is needed.
5. **Track:** finished chunks are recorded in `<file>.state`, which is written atomically. Re-running skips them.
6. **Verify:** optionally hashes the finished file and compares it to the expected SHA256.

## Will it make my downloads faster?

**Only if the server limits speed per connection.** Many servers do, and that is where parallel connections help most. If a single connection already uses your whole internet line, more connections won't help, because they all share the same bandwidth.

Quick test: download with `-c 1`, then `-c 16`, and compare the speeds.

**8–16 connections is the sweet spot.** Going higher rarely helps, and some servers throttle or block clients that open too many connections.

## Stopping and resuming

- Press **Ctrl+C**. Progress is saved after every chunk.
- Run the same command again, or use the same URL and save location in interactive mode, and it continues from where it stopped.
- Until it finishes, the output file shows its **full size** because it's pre-allocated. **Don't open or use it until you see `Done`.**

## Limitations

- Works with direct HTTP/HTTPS file links only. It doesn't work with streaming sites, torrents, or game launchers like Steam (which already download in parallel).
- Every mirror must serve the **exact same file**. Mirrors with a different size are skipped automatically.
- Please be considerate: don't hammer small or free servers with a large number of connections.

## License

[MIT](LICENSE): free to use, modify and share.
