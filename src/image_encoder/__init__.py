"""PNG LSB image encoder for the INF2005 steganography workflow."""

from .encoder import (
    FRAME_MAGIC,
    HEADER_MAGIC,
    ImageEncodeResult,
    check_capacity,
    encode_image_file,
    frame_payload,
    header_length_bytes,
    image_capacity_bits,
    resolve_header_start_channel,
    resolve_payload_start_channel,
)

__all__ = [
    "FRAME_MAGIC",
    "HEADER_MAGIC",
    "ImageEncodeResult",
    "check_capacity",
    "encode_image_file",
    "frame_payload",
    "header_length_bytes",
    "image_capacity_bits",
    "resolve_header_start_channel",
    "resolve_payload_start_channel",
]
