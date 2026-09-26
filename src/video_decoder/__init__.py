"""Video decoder and verification for the INF2005 steganography workflow."""

from .decoder import (
    VideoDecodeResult,
    decode_video_file,
)

__all__ = [
    "VideoDecodeResult",
    "decode_video_file",
]
