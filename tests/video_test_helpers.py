"""Shared setup for the video tests (not a test file itself).

Test clips are generated with ffmpeg, so no big video files go in the repo.
Each clip is a normal MP4 (H.264 video + AAC audio), like one downloaded
from the internet.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from crypto_payload import generate_ed25519_keypair
from video_stego import encode_video_file
from video_stego.video_processing import FFMPEG

MEDIA_ID = "VIDEO-TEST"
SECRET = b"test-secret"
LSB_DEPTH = 1


def make_test_video(path: Path, with_audio: bool = True, seconds: int = 2) -> Path:
    """Create a small test clip: a moving test pattern, plus a beep if with_audio."""
    args = ["-f", "lavfi", "-i", f"testsrc=duration={seconds}:size=160x120:rate=15"]
    if with_audio:
        args += ["-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}", "-c:a", "aac"]
    args += ["-c:v", "libx264", "-pix_fmt", "yuv420p", "-shortest", str(path)]

    command = [FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin", "-y", *args]
    subprocess.run(command, check=True, capture_output=True)
    return path


class VideoTestCase(unittest.TestCase):
    """Gives each test class a temp folder, a signing keypair, a cover clip and
    one genuine stego video. Making videos is the slow part, so it happens once
    per class; tests write their own copies and never modify these."""

    @classmethod
    def setUpClass(cls) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp_dir.cleanup)
        cls.folder = Path(temp_dir.name)

        cls.private_key_pem, cls.public_key_pem = generate_ed25519_keypair()
        cls.cover = make_test_video(cls.folder / "cover.mp4")
        cls.stego = encode_video_file(
            cls.cover, cls.folder / "stego.mp4", media_id=MEDIA_ID,
            private_key_pem=cls.private_key_pem, start_secret=SECRET, lsb_depth=LSB_DEPTH,
            note="hello from video",
        ).output_path
