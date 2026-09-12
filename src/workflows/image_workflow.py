"""Image workflow: wires crypto_payload + image_encoder/image_decoder together.

No GUI toolkit here, so the GUI, a demo script, or tests can all call it the same way.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from PIL import Image

from crypto_payload import build_payload, sign_payload
from image_decoder import ImageDecodeResult, decode_image_file
from image_encoder import (
    ImageEncodeResult,
    check_capacity,
    encode_image_file,
    frame_payload,
    header_length_bytes,
    image_capacity_bits,
)

_RGB_CHANNELS = 3


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


def build_signed_envelope(cover_path: Path, media_id: str, note: str, private_key_pem: bytes, lsb_depth: int) -> bytes:
    """Hash the cover file, build the FR3 payload, and sign it (FR4).

    The verifier only ever has the stego file, never the original cover, so
    the hash must be reproducible from the stego file alone. It's computed
    with the low `lsb_depth` bits masked out of every RGB channel — exactly
    the bits embedding is allowed to touch — matching the convention
    `image_decoder.decode_image_file` expects on the other side.
    """
    media_hash = _masked_cover_hash(cover_path, lsb_depth)
    metadata = {"note": note} if note else {}
    payload = build_payload(media_id, media_hash, metadata, datetime.now(UTC))
    return sign_payload(payload, private_key_pem)


def _masked_cover_hash(cover_path: Path, lsb_depth: int) -> bytes:
    """SHA-256 of the cover with the low `lsb_depth` bits masked out of every
    RGB channel. Must match image_decoder's masking exactly, or a genuine,
    untouched round trip would incorrectly come back as Tampered.
    """
    keep_mask = (0xFF << lsb_depth) & 0xFF
    with Image.open(cover_path) as source:
        image = source.convert("RGB")
        width, height = image.size
        pixels = image.load()
        assert pixels is not None, "a just-opened, just-converted image always has pixel data"
        buf = bytearray(width * height * _RGB_CHANNELS)
        i = 0
        for y in range(height):
            for x in range(width):
                pixel = pixels[x, y]
                assert isinstance(pixel, tuple), "RGB-mode images always yield an (R, G, B) tuple per pixel"
                for channel in range(_RGB_CHANNELS):
                    buf[i] = pixel[channel] & keep_mask
                    i += 1
    return hashlib.sha256(bytes(buf)).digest()


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


def decode_image(
    stego_path: Path | str,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> ImageDecodeResult:
    return decode_image_file(
        stego_path, lsb_depth=lsb_depth, start_secret=start_secret, media_id=media_id, public_key_pem=public_key_pem
    )
