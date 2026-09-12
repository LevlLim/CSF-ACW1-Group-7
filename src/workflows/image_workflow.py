"""Image workflow: wires crypto_payload + image_encoder together.

No GUI toolkit here, so the GUI, a demo script, or tests can all call it the same way.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from PIL import Image

from crypto_payload import build_payload, sign_payload
from image_encoder import (
    ImageEncodeResult,
    check_capacity,
    encode_image_file,
    frame_payload,
    header_length_bytes,
    image_capacity_bits,
)


class CapacityStatus:
    """Whether a signed envelope fits in a cover image at a given LSB depth."""

    def __init__(self, fits: bool, needed_bits: int, capacity_bits: int) -> None:
        self.fits = fits
        self.needed_bits = needed_bits
        self.capacity_bits = capacity_bits


def image_dimensions(cover_path: Path) -> tuple[int, int]:
    with Image.open(cover_path) as image:
        return image.size


def capacity_bits(width: int, height: int, lsb_depth: int) -> int:
    return image_capacity_bits(width, height, lsb_depth)


def build_signed_envelope(cover_path: Path, media_id: str, note: str, private_key_pem: bytes) -> bytes:
    """Hash the cover file, build the FR3 payload, and sign it (FR4)."""
    media_hash = hashlib.sha256(cover_path.read_bytes()).digest()
    metadata = {"note": note} if note else {}
    payload = build_payload(media_id, media_hash, metadata, datetime.now(UTC))
    return sign_payload(payload, private_key_pem)


def check_image_capacity(cover_path: Path, envelope: bytes, lsb_depth: int) -> CapacityStatus:
    """Report whether the framed envelope (locator header + payload) fits."""
    width, height = image_dimensions(cover_path)
    framed_length = len(frame_payload(envelope))
    needed_bits = (header_length_bytes() + framed_length) * 8
    return CapacityStatus(
        fits=check_capacity(width, height, envelope, lsb_depth),
        needed_bits=needed_bits,
        capacity_bits=capacity_bits(width, height, lsb_depth),
    )


def encode_image(
    cover_path: Path,
    stego_path: Path | str,
    envelope: bytes,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
) -> ImageEncodeResult:
    return encode_image_file(
        cover_path, stego_path, envelope, lsb_depth=lsb_depth, start_secret=start_secret, media_id=media_id
    )


def decode_image_stub(*args: object, **kwargs: object) -> None:
    """Image extraction isn't built yet — replace this call once it is.

    Raises so the GUI shows a clear message instead of doing nothing.
    """
    raise NotImplementedError("Image extraction/verification is not implemented yet.")
