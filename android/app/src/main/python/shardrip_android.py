"""Glue between the Android app (Java) and shardrip.py.

The app runs Shardrip's web interface on 127.0.0.1 inside the app and shows it full-screen.
Nothing is reachable from other devices (it only listens on the phone itself).
"""
import os

_server = _state = _url = None


def start(download_dir):
    """Start Shardrip (once) and return the address the app should show."""
    global _server, _state, _url
    os.environ["SHARDRIP_APP"] = "android"
    os.environ["SHARDRIP_DOWNLOAD_DIR"] = download_dir
    import shardrip
    if _server is None:
        _server, _state, _url, _ = shardrip.start_web_server(7777, False, 50)
    return _url


def _tab():
    return _state.tabs["dl"] if _state else None


def busy():
    t = _tab()
    return bool(t and t.running)


def percent():
    t = _tab()
    p = t.progress if t else None
    return int(p.snapshot()[4]) if p else 0


def status():
    import shardrip
    t = _tab()
    if not t:
        return "Starting…"
    p = shardrip._progress_json(t.progress)
    if p and p["pct"] < 100:
        pre = f"{p['label']}: " if p["label"] else ""
        return f"{pre}{p['pct']}%  ·  {p['done']} / {p['total']}  ·  {p['speed']}/s  ·  ETA {p['eta']}"
    return t.status or "Working…"
