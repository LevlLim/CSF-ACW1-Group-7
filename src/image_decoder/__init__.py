"""PNG LSB image decoder and verification for the INF2005 steganography workflow."""

from .decoder import (
    ImageDecodeResult,
    decode_image_file,
)

__all__ = [
    "ImageDecodeResult",
    "decode_image_file",
]