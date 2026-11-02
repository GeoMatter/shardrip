# Shardrip as an app: double-click to open the full Shardrip app in its own window
# (Download, Send, QR scan / upload a QR image, Lock...). No terminal.
# This is what Shardrip.exe runs. Keep it in the same folder as shardrip.py.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shardrip  # noqa: E402

if "--selftest" in sys.argv:
    # Used by the automatic build to check the packaged .exe works.
    # (A windowed .exe has no console, so results go to a file.)
    i = sys.argv.index("--selftest")
    out = sys.argv[i + 1] if len(sys.argv) > i + 1 else "selftest.txt"
    results = shardrip.self_test()
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(results) + "\n")
    sys.exit(0 if all(r.startswith("PASS") for r in results) else 1)

if "--classic" in sys.argv:
    shardrip.gui_main()  # the older Tk window
else:
    shardrip.app_main()
