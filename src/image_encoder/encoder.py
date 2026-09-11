"""PNG LSB embedding helpers used by the GUI image encoder tab."""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from pathlib import Path
from typing import Iterable

from PIL import Image

from crypto_payload import derive_start_location

FRAME_MAGIC = b"CSFIMG1"
HEADER_MAGIC = b"CSFHDR1"
_LENGTH_BYTES = 4
_RGB_CHANNELS = 3


@dataclass(frozen=True, slots=True)
class ImageEncodeResult:
    """Non-secret details that a GUI can display after image encoding."""

    stego_path: Path
    media_id: str
    lsb_depth: int
    capacity_bits: int
    embedded_bits: int
    embedded_channels: int
    changed_channel_values: int
    changed_pixels: int


def frame_payload(payload: bytes) -> bytes:
    """Wrap signed payload bytes with a decoder-friendly magic and length."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("payload is too large for the image frame header")
    return FRAME_MAGIC + len(payload).to_bytes(_LENGTH_BYTES, "big") + payload


def image_capacity_bits(width: int, height: int, lsb_depth: int) -> int:
    """Return usable RGB LSB capacity for a PNG image."""
    _validate_lsb_depth(lsb_depth)
    if width <= 0 or height <= 0:
        raise ValueError("image dimensions must be positive")
    return width * height * _RGB_CHANNELS * lsb_depth


def check_capacity(width: int, height: int, payload: bytes, lsb_depth: int) -> bool:
    """Return whether a locator header and framed payload fit in RGB LSBs."""
    framed = frame_payload(payload)
    hidden_bytes = len(_locator_header(len(framed))) + len(framed)
    return hidden_bytes * 8 <= image_capacity_bits(width, height, lsb_depth)


def header_length_bytes() -> int:
    """Return the fixed locator header length Person 2 must extract first."""
    return len(HEADER_MAGIC) + _LENGTH_BYTES


def resolve_header_start_channel(
    width: int,
    height: int,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
) -> int:
    """Return the secret-derived RGB channel where the locator header starts."""
    capacity_channels = _capacity_channels(width, height, lsb_depth)
    header_channels = ceil(header_length_bytes() * 8 / lsb_depth)
    return derive_start_location(
        start_secret,
        f"{media_id}:header",
        "image",
        capacity_channels,
        header_channels,
    )


def resolve_payload_start_channel(
    width: int,
    height: int,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    framed_length: int,
) -> int:
    """Return the secret-derived RGB channel where the framed payload starts."""
    if framed_length <= 0:
        raise ValueError("framed_length must be positive")
    capacity_channels = _capacity_channels(width, height, lsb_depth)
    header_channels = ceil(header_length_bytes() * 8 / lsb_depth)
    embedded_channels = ceil(framed_length * 8 / lsb_depth)
    header_start = resolve_header_start_channel(width, height, lsb_depth, start_secret, media_id)
    start_channel = derive_start_location(
        start_secret,
        media_id,
        "image",
        capacity_channels,
        embedded_channels,
    )
    return _avoid_range_overlap(
        start_channel,
        embedded_channels,
        header_start,
        header_channels,
        capacity_channels,
    )


def encode_image_file(
    cover_path: str | Path,
    stego_path: str | Path,
    payload: bytes,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
) -> ImageEncodeResult:
    """Embed framed payload bytes in a PNG using row-major RGB LSB replacement.

    ``payload`` should be the signed envelope produced by Person 5's
    ``crypto_payload.sign_payload``. The start channel is HMAC-derived from the
    secret, media ID, image capacity, and framed payload length; it is not
    written into the image.
    """
    cover = Path(cover_path)
    stego = Path(stego_path)
    _validate_lsb_depth(lsb_depth)
    if not media_id:
        raise ValueError("media_id must be non-empty")

    with Image.open(cover) as source:
        if source.format != "PNG":
            raise ValueError("only PNG cover images are supported")
        image = _editable_rgb_image(source)

    width, height = image.size
    framed = frame_payload(payload)
    header = _locator_header(len(framed))
    header_bits = tuple(_bytes_to_bits(header))
    payload_bits = tuple(_bytes_to_bits(framed))
    capacity_bits = image_capacity_bits(width, height, lsb_depth)
    if len(header_bits) + len(payload_bits) > capacity_bits:
        raise ValueError("payload does not fit in this image at the selected LSB depth")

    header_channels = ceil(len(header_bits) / lsb_depth)
    embedded_channels = ceil(len(payload_bits) / lsb_depth)
    header_start = resolve_header_start_channel(
        width,
        height,
        lsb_depth,
        start_secret,
        media_id,
    )
    start_channel = resolve_payload_start_channel(
        width,
        height,
        lsb_depth,
        start_secret,
        media_id,
        len(framed),
    )

    pixels = image.load()
    header_changes = _embed_bits(pixels, width, header_start, header_bits, lsb_depth)
    payload_changes = _embed_bits(pixels, width, start_channel, payload_bits, lsb_depth)
    changed_pixel_positions = header_changes[1] | payload_changes[1]

    stego.parent.mkdir(parents=True, exist_ok=True)
    image.save(stego, format="PNG")
    return ImageEncodeResult(
        stego_path=stego,
        media_id=media_id,
        lsb_depth=lsb_depth,
        capacity_bits=capacity_bits,
        embedded_bits=len(header_bits) + len(payload_bits),
        embedded_channels=header_channels + embedded_channels,
        changed_channel_values=header_changes[0] + payload_changes[0],
        changed_pixels=len(changed_pixel_positions),
    )


def _locator_header(framed_length: int) -> bytes:
    return HEADER_MAGIC + framed_length.to_bytes(_LENGTH_BYTES, "big")


def _capacity_channels(width: int, height: int, lsb_depth: int) -> int:
    _validate_lsb_depth(lsb_depth)
    if width <= 0 or height <= 0:
        raise ValueError("image dimensions must be positive")
    return width * height * _RGB_CHANNELS


def _embed_bits(
    pixels: object,
    width: int,
    start_channel: int,
    bits: tuple[int, ...],
    lsb_depth: int,
) -> tuple[int, set[tuple[int, int]]]:
    changed_channels = 0
    changed_pixels: set[tuple[int, int]] = set()
    mask = (1 << lsb_depth) - 1
    bit_index = 0
    channels_needed = ceil(len(bits) / lsb_depth)

    for channel_index in range(start_channel, start_channel + channels_needed):
        x, y, channel = _channel_position(channel_index, width)
        pixel = list(pixels[x, y])
        old_value = pixel[channel]
        chunk = bits[bit_index : bit_index + lsb_depth]
        new_value = (old_value & ~mask) | _bits_to_value(chunk, lsb_depth)
        if new_value != old_value:
            pixel[channel] = new_value
            pixels[x, y] = tuple(pixel)
            changed_channels += 1
            changed_pixels.add((x, y))
        bit_index += lsb_depth

    return changed_channels, changed_pixels


def _avoid_range_overlap(
    start: int,
    length: int,
    blocked_start: int,
    blocked_length: int,
    capacity: int,
) -> int:
    if start + length <= blocked_start or blocked_start + blocked_length <= start:
        return start
    after = blocked_start + blocked_length
    if after + length <= capacity:
        return after
    before = blocked_start - length
    if before >= 0:
        return before
    raise ValueError("image is too small for separated locator and payload regions")


def _editable_rgb_image(source: Image.Image) -> Image.Image:
    """Return a mutable RGB/RGBA image while preserving alpha when present."""
    if source.mode in {"RGB", "RGBA"}:
        return source.copy()
    return source.convert("RGBA" if "A" in source.getbands() else "RGB")


def _bytes_to_bits(data: bytes) -> Iterable[int]:
    for byte in data:
        for bit in range(7, -1, -1):
            yield (byte >> bit) & 1


def _bits_to_value(bits: tuple[int, ...], width: int) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value << (width - len(bits))


def _channel_position(channel_index: int, width: int) -> tuple[int, int, int]:
    pixel_index, channel = divmod(channel_index, _RGB_CHANNELS)
    y, x = divmod(pixel_index, width)
    return x, y, channel


def _validate_lsb_depth(lsb_depth: int) -> None:
    if not isinstance(lsb_depth, int) or not 1 <= lsb_depth <= 8:
        raise ValueError("lsb_depth must be an integer from 1 to 8")
