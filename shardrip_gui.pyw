# Double-click this file to open the Shardrip window without a terminal behind it.
# (.pyw files run with pythonw.exe on Windows - no console window.)
# Keep it in the same folder as shardrip.py.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shardrip  # noqa: E402

shardrip.gui_main()
