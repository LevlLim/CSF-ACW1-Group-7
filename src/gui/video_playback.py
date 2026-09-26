"""Open a video in the system's default player.

customtkinter can't play video inside the window, so cover-vs-stego playback
(spec: "play/display both cover and stego objects for comparison") opens
each file in the normal player, next to the first-frame thumbnails in the GUI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def open_in_default_player(path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore[attr-defined]  # Windows-only API
    elif sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=True)
    else:
        subprocess.run(["xdg-open", str(path)], check=True)
