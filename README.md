# ⚡ Shardrip

A free, open-source **multi-connection downloader and file sender** in a single Python file.

- **Download:** splits big files into chunks, downloads them in parallel (optionally from several mirrors), resumes after interruptions, and verifies the result with SHA256.
- **Send:** shares a file straight from your PC with a public link, with no port forwarding, even behind CGNAT. It shows a **QR code** for phones, and can **lock** the file with a password.
- **Window, browser or terminal:** use the terminal menu, the Windows **GUI**, or the **web interface** in any browser, including on **Android phones**.

It does the same job as paid "download accelerators" and "send large files" services, with no ads, no account and no upload limits.

```
[##############           ]  58.8%  2.76 GB/4.70 GB  4.26 MB/s (34 Mbps)  ETA 6m24s
```

## Features

| | |
|---|---|
| **Parallel connections** | Up to 32 simultaneous HTTP Range requests |
| **Multiple mirrors** | Spread chunks across several servers hosting the same file |
| **Resume** | Stop at any time (Ctrl+C, crash, power cut) and run it again to continue |
| **SHA256 verification** | Confirms the download isn't corrupted or tampered with |
| **Send mode** | Public `https` link via a free Cloudflare tunnel. No router changes |
| **Smart links** | One link/QR: downloads straight over your Wi-Fi when you're near the sender (full speed), over the internet when you're not, and switches mid-download if you leave or come back |
| **QR code** | Scan the send link with a phone, in the terminal or the window |
| **Lock** | Password encryption (AES-256-GCM). Only someone with the password can read the file |
| **GUI** | Download and Send tabs, progress bar, Copy buttons, QR code |
| **Web interface** | The same app in any browser, phone-friendly |
| **Android app** | `Shardrip.apk`: download with QR scan, smart links and background downloads |
| **QR scanner** | In the web interface: scan the sender's QR with your camera, and the link fills itself in |
| **Safe by default** | Never overwrites a finished file without asking. Detects if a file changed on the server before resuming |
| **One file** | Needs `requests` (and `cryptography` for Lock). Both install themselves on first use |

## Quick start

**Requirements:** Python 3.9+

| Want | Do |
|---|---|
| **⭐ The app (everything, incl. QR scan)** | Double-click **`Shardrip.exe`** (no Python), or `shardrip_gui.pyw`, or `python shardrip.py --gui` |
| **In your browser** | `python shardrip.py --web` (opens automatically) |
| **The terminal menu** | Double-click `shardrip.py`, or run `python shardrip.py` |

```
========================================================
  ⚡ SHARDRIP 2.3 - multi-connection downloader
========================================================
  1) Download a file
  2) Send a file to someone
  3) Open the window (GUI)
  4) Open in your web browser (works on phones too)
  Choose [1]:
```

**1) Download a file** asks:

```
  Download URL: https://example.com/big-file.iso
  Extra mirror URL (Enter to skip):
  Save folder (B = browse) [C:\Users\you\Downloads]:
  File name [big-file.iso]:
  Connections (1-32) [16]:
  SHA256 to verify (Enter to skip):
```

**2) Send a file to someone** asks:

```
  File to send (drag it in, or B = browse): C:\Users\you\Videos\clip.mp4
  Port [8080]:
  Public internet link via Cloudflare? (Y/n) [y]:
  Lock with a password? (Enter = no, G = generate one, or type your own):
```

Press **Enter** to accept a default. Type **B** to open a folder or file picker.

> **Tip:** if dragging a file into the terminal shows a 🚫 cursor, the terminal is running **as Administrator**. Windows blocks drag-and-drop into admin windows. Use a normal terminal, or type **B**.

## The window (GUI)

`shardrip_gui.pyw` opens the window **without** a terminal behind it (keep it in the same folder as `shardrip.py`).

- **⬇ Download tab:** paste a link, pick a folder, and press **Start**. It shows a live progress bar, speed in MB/s and Mbps, and an ETA. **Stop** saves progress, and **Start** again resumes. If the file is locked and you didn't type the password, it asks for it.
- **⬆ Send tab:** pick a file and press **Start sharing**. You get the links, a **Copy** button for each, the receiver's command, and a **QR code**. Tick **Lock with password** to encrypt (**Generate** makes a strong one).

## The web interface (any browser, phones too)

```bash
python shardrip.py --web
```

Shardrip starts a small **private** web page on your own device and opens it in your browser. It has the same **Download / Send** tabs as the window, sized for phone screens, with a file browser, progress bar, Copy buttons, QR code and Lock.

```
================================================================
  ⚡ SHARDRIP 2.3 - web interface is running
================================================================
  Open this in your browser:
    http://127.0.0.1:7777/?key=fvcRFY7HeHlMmSV4_6J-xg
  Keep this window open while you use it. Ctrl+C to quit.
```

| Option | Description | Default |
|---|---|---|
| `--web` | Start the web interface | off |
| `--web-port` | Port for the page | 7777 |
| `--lan` | Also allow **other devices on your Wi-Fi** (e.g. control your PC from your phone). Prints a QR to scan | off (this device only) |
| `--no-browser` | Don't open the browser automatically | off |

### 📷 Scan a QR code instead of typing the link

On the **⬇ Download** tab, tap **📷 Scan QR** and point your camera at the QR code on the sender's screen, **or tap 🖼 Upload QR image** and pick a screenshot or photo of it (e.g. one sent to you on WhatsApp). The link and file name fill in by themselves. If the file is **locked**, Shardrip jumps to the password box: type the password the sender gave you (it's never inside the QR) and press **Start download**.

- **Live camera** works when the page runs on the same device, like Shardrip on your phone in Termux, or on your PC with a webcam.
- No webcam, or using `--lan` (where browsers block the camera on plain `http` pages)? **🖼 Upload QR image** always works.
- Scanning uses the browser's built-in QR reader where there is one, and the embedded [jsQR](https://github.com/cozmo/jsQR) library otherwise. See `THIRD-PARTY-NOTICES.md`.

**Security:**
- **By default only your own device can open it.** It listens on `127.0.0.1`, so nothing on your network can reach it.
- The link contains a **private random key**. Without it, the page and every action are refused.
- Actions need the key in a special header that other websites can't send, so a malicious site can't silently control Shardrip in the background. The page also rejects requests made through a different web address (DNS-rebinding protection).
- With `--lan`, **anyone who has the link can control Shardrip on that machine**, including choosing files to share. Only use it on your own network and don't share that link.

## 📱 Android app (Shardrip.apk)

Every [release](../../releases/latest) includes **`Shardrip.apk`**, built and tested on an Android emulator by GitHub Actions. No Termux, no Python, no browser.

1. On your phone, open the release page and tap **Shardrip.apk**.
2. Android asks to allow installing from your browser: **Settings → Allow from this source**, then **Install**.
3. Open **Shardrip**: paste a link, **📷 Scan QR**, or **🖼 Upload QR image**, type the password if it's locked, and press **Start download**.

- **Smart links work**: on the sender's Wi-Fi it downloads directly at full speed, elsewhere over the internet.
- **Keeps going in the background**: a "Shardrip - downloading" notification shows progress, and the phone stays awake until it's done.
- Files save to your phone's **Download** folder.
- **Share a link to Shardrip** from WhatsApp/Chrome (Share → Shardrip) and it fills itself in.
- Version 1 is **download-only**. To *send* from a phone, use Termux (below).
- Needs Android 8+ on a 64-bit phone (nearly every phone from the last 7+ years). Not on the Play Store, so Play Protect may warn about an unknown app.

## 📱 Android (Termux)

Shardrip also runs on Android inside **Termux** (this way can also **send** files). Use the **web interface** there: the window version needs a desktop.

1. Install **Termux from F-Droid** (f-droid.org), **not the Play Store**. The Play Store version is outdated.
2. In Termux:
   ```bash
   pkg update && pkg upgrade -y
   pkg install -y python python-cryptography cloudflared
   pip install requests
   termux-setup-storage          # allow access so downloads land in your phone's Downloads folder
   curl -LO https://raw.githubusercontent.com/GeoMatter/shardrip/main/shardrip.py
   python shardrip.py --web
   ```
3. Your browser opens the page (or copy the link it prints into Chrome).

**Phone tips:**
- Run `termux-wake-lock` before a long download so Android doesn't stop Termux when the screen turns off, and `termux-wake-unlock` afterwards.
- Downloads save to your phone's **Downloads** folder by default (`~/storage/downloads`).
- 16 connections can use a lot of mobile data fast. Use Wi-Fi for big files.

## Download from the command line

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
| `--password` | Password for a **locked** file (otherwise you're asked) | none |
| `--overwrite` | Replace an existing file without asking | off (asks first) |
| `--via` | For Shardrip smart links: `auto` (same network if possible, else internet), `lan` or `internet` | auto |

**Example: Kali Linux ISO**

```bash
python shardrip.py "https://cdimage.kali.org/kali-2026.3/kali-linux-2026.3-installer-amd64.iso" \
  -o kali.iso -c 16 \
  --sha256 db9cbed33edb45727d16911813c2434fcd1419585007884153be22a03b30ec2f
```

**Finding a direct link:** start the download in your browser, open the downloads list (**Ctrl+J**), right-click it, and choose **Copy download link**.

## Send a file to someone

```bash
python shardrip.py --serve "C:\path\to\file.iso"          # plain
python shardrip.py --serve "C:\path\to\file.iso" --lock   # encrypted, password generated for you
```

```
================================================================
  ⚡ SHARING - send the receiver one of these links:
================================================================
  Smart link - Wi-Fi when nearby, internet otherwise:
    https://random-words.trycloudflare.com/Xk3.../file.iso?lan=192.168.1.50:8080
  Internet only:
    https://random-words.trycloudflare.com/Xk3.../file.iso
  Same network (LAN):
    http://192.168.1.50:8080/Xk3.../file.iso

  SHA256: db9cbed3...

  Receiver runs:
    python shardrip.py "https://random-words.trycloudflare.com/Xk3.../file.iso?lan=192.168.1.50:8080" --sha256 db9cbed3...
================================================================
  Scan to open the link on a phone:

  █████████████████████████████
  ██ ▄▄▄▄▄ █▀ ▄▀█▄█ █ ▄▄▄▄▄ ██
  ██ █   █ █▄▀▄ ▀▀▄▀█ █   █ ██
  ...
```

| Option | Description | Default |
|---|---|---|
| `--serve FILE` | Share FILE | none |
| `--lock` | Encrypt with a generated password (shown on screen) | off |
| `--password PW` | Encrypt with your own password | none |
| `--port` | Local port for the file server | 8080 |
| `--no-tunnel` | No public link: LAN (and Tailscale, if installed) only | off |
| `--no-qr` | Don't print the QR code | off |

**How it works over the internet:** Shardrip starts a small file server on your PC and opens a free [Cloudflare Quick Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/). Your PC connects *out* to Cloudflare, so you need **no port forwarding, no router changes and no account**, and it works behind CGNAT. `cloudflared` (Cloudflare's official tunnel client) is downloaded automatically from its GitHub releases on first use.

### Smart links (same Wi-Fi = full speed, automatically)

The first link (and the QR code) is a **smart link**: the internet link with your PC's local addresses tucked on the end (`?lan=…`). A receiver using Shardrip 2.5+:

| Situation | What happens |
|---|---|
| On the **same Wi-Fi/network** as the sender | Downloads **directly** over the local network - full Wi-Fi/LAN speed, never through your internet connection or its speed cap |
| **Somewhere else** | Uses the internet (Cloudflare) link |
| **Leaves** the network mid-download | Switches to the internet link and keeps going |
| **Comes back** | Switches back to the local link (checked every 30 s) |

- If your PC has **several adapters** (Wi-Fi, Ethernet, VPN), all its addresses are included and the receiver uses whichever one answers.
- To force it: **Connect via** on the Download tab (*Auto* / *Same network only* / *Internet only*), or `--via auto|lan|internet` on the command line.
- The Send tab's QR code has the same three choices.
- **Old Shardrip versions and browsers just use the internet link** - a smart link always works as a normal link too.

**Good to know:**
- **Your upload speed is the limit.** Many home plans upload much slower than they download, and no number of connections can beat that.
- **The link contains a random secret path**, so it can't be guessed. But **anyone you give the link to can download the file while sharing is on.** Stop sharing and the link dies.
- **Quick Tunnels are a free Cloudflare service with no uptime guarantee.** They're great for one-off transfers. If the tunnel won't start, the LAN and Tailscale links still work.
- **Tailscale:** if it's installed, a Tailscale link is shown too, as a private alternative to the public link.

## 🔒 Lock (password encryption)

With Lock on, the file is **encrypted on the fly as it's sent**. There's no extra copy on your disk and no waiting before the link appears. Anyone who grabs the link without the password, **including Cloudflare**, only gets scrambled data.

1. **Sender:** turn Lock on (`--lock`, menu option **G**, or the GUI checkbox). Share the **link** and the **password** separately: for example, text the link and say the password on a call.
2. **Receiver:** downloads with Shardrip as normal. When the download finishes, Shardrip asks for the password, unlocks the file, and deletes the locked copy.

**Details:**
- **AES-256-GCM** in 1 MiB blocks, with the key derived from the password using **scrypt** and a fresh random salt for every share. Every block is authenticated, so a corrupted or tampered file is **detected**, never silently accepted.
- **Wrong password?** The download is kept. Run the same command again with the right password and it unlocks without re-downloading.
- **Receivers need Shardrip.** A browser download of a locked link gives a `.shardlock` file that only Shardrip can open.
- **Unlocking needs free disk space** for both the locked and unlocked copies until it finishes.
- **Use a strong password.** The generated ones (like `kp7x-9qmr-w3hd-t8ne`) are random and strong. A short word-based password can be guessed offline by someone who has the file.

## How downloading works

1. **Probe:** asks the server for the file size and checks it supports HTTP Range requests.
2. **Split:** divides the file into fixed-size chunks (16 MB by default).
3. **Download:** a pool of worker threads requests `Range: bytes=start-end` for each chunk, rotating across mirrors. Failed chunks retry with backoff and switch to another mirror.
4. **Write:** each chunk is written directly to its position in a pre-allocated file, so no merge step is needed.
5. **Track:** finished chunks are recorded in `<file>.state`, which is written atomically. Re-running skips them.
6. **Verify:** checks the SHA256 if you gave one, and unlocks the file if it's locked.

## Will it make my downloads faster?

**Only if the server limits speed per connection.** Many servers do, and that is where parallel connections help most. If one connection already uses your whole internet line, more connections won't help, because they all share the same bandwidth.

**Speeds come in two units.** Internet plans use **Mbps** (mega*bits*), and downloads show **MB/s** (mega*bytes*). 1 byte = 8 bits, so **divide your plan by 8**: a 40 Mbps plan tops out around **5 MB/s**. Shardrip shows both.

Quick test: download with `-c 1`, then `-c 16`, and compare the speeds. **8–16 connections is the sweet spot.**

## Stopping and resuming

- Press **Ctrl+C** (or **Stop** in the window). Progress is saved after every chunk.
- Run it again with the **same save location and file name** to continue.
- **Link expired?** (`HTTP 403`/`410`) Get a fresh link and run it again with the same file name. It still resumes, because progress is tracked per file, not per link.
- If the file on the server **changed** since last time, Shardrip notices and starts fresh instead of mixing two versions.
- Until it finishes, the output file shows its **full size** because it's pre-allocated. **Don't use it until you see `Done`.**
- **A finished file is never overwritten by accident.** Shardrip checks it against `--sha256` (if given), or asks before replacing it.

## Limitations

- Downloads work with direct HTTP/HTTPS file links only. Not streaming sites, torrents, or game launchers like Steam (which already download in parallel).
- Every mirror must serve the **exact same file**. Mirrors with a different size are skipped automatically.
- Please be considerate: don't hammer small or free servers with a large number of connections.

## Shardrip.exe (no Python needed)

Every [release](../../releases/latest) includes **`Shardrip.exe`**, built automatically on Windows by GitHub Actions and self-tested before it's published. Download it and double-click: no Python, no setup, **no browser**. It's a normal Windows app.

- **⬇ Download tab:** paste a link, or **📷 Scan QR** with your webcam, or **🖼 Upload QR image** (a screenshot or photo, e.g. from WhatsApp). The link fills itself in; for locked files, type the password and press Start.
- **⬆ Send tab:** pick a file and press **Start sharing**. You get the link, a QR code and Copy buttons. Lock it with a password if you want.
- Windows may say **"Windows protected your PC"**, because the app isn't paid-signed. Click **More info → Run anyway**.
- Prefer Python, or on Mac/Linux/Android? Use `shardrip.py` from **Source code (zip)**. Double-clicking `shardrip_gui.pyw` opens the same app. QR scanning with Python installs OpenCV automatically the first time (`opencv-python-headless`).

## License

[MIT](LICENSE): free to use, modify and share. Includes jsQR (Apache-2.0); see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
