"""PNG LSB extraction and verification, matching encoder.py's wire format.

TEAM CONVENTION for media_hash (was an open question, now resolved):
    ``VerificationPayload.media_hash`` must be reproducible from the STEGO
    file alone, since per the spec's own demo scenario Party B only ever
    receives the stego file (never the original cover). The convention used
    here uses ``image_encoder.stable_image_hash`` to mask out the low
    ``lsb_depth`` bits of every RGB channel before hashing, since those are
    exactly the bits LSB embedding is allowed to touch. The encoder and
    decoder call that same helper so their hash representations cannot drift.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from crypto_payload import (
    CryptoPayloadError,
    SerializationFormatError,
    Verdict,
    VerificationPayload,
    parse_and_verify,
    verdict_for_error,
)
from image_encoder import (
    FRAME_MAGIC,
    HEADER_MAGIC,
    header_length_bytes,
    image_capacity_bits,
    resolve_header_start_channel,
    resolve_payload_start_channel,
    stable_image_hash,
)

_RGB_CHANNELS = 3
_LENGTH_BYTES = 4


class LocatorNotFoundError(SerializationFormatError):
    """Raised when the selected decoder settings cannot locate a payload."""


class PayloadFrameError(SerializationFormatError):
    """Raised when a locator exists but its payload frame is malformed."""


def _channel_position(channel_index: int, width: int) -> tuple[int, int, int]:
    """Mirrors image_encoder's private channel-to-pixel mapping exactly:
    row-major pixels, 3 RGB channels per pixel, channel-minor ordering."""
    pixel_index, channel = divmod(channel_index, _RGB_CHANNELS)
    y, x = divmod(pixel_index, width)
    return x, y, channel


@dataclass(frozen=True, slots=True)
class ImageDecodeResult:
    """What the GUI needs to display after image decoding (FR10)."""

    verdict: Verdict
    payload: VerificationPayload | None
    error: Exception | None


def decode_image_file(
    stego_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> ImageDecodeResult:
    """Extract, verify, and produce a verdict for a stego PNG.

    ``lsb_depth``, ``start_secret``, and ``media_id`` must be the same
    values used at encode time — these are agreed out-of-band (e.g. known
    to both parties, not derived from the file itself), exactly like
    Person 1's ``encode_image_file`` requires them as inputs.
    """
    error: Exception | None = None
    hash_matches: bool | None = None
    payload: VerificationPayload | None = None

    try:
        payload, hash_matches = _decode_and_verify(
            stego_path, lsb_depth=lsb_depth, start_secret=start_secret,
            media_id=media_id, public_key_pem=public_key_pem,
        )
    except CryptoPayloadError as exc:
        error = exc
    except (OSError, ValueError) as exc:
        # Anything from PIL / bad file / bad dimensions -> treat as
        # "we could not make sense of this as a signed stego image".
        error = SerializationFormatError(str(exc))

    verdict = verdict_for_error(error, hash_matches)
    return ImageDecodeResult(verdict=verdict, payload=payload, error=error)


def _decode_and_verify(
    stego_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> tuple[VerificationPayload, bool]:
    if not isinstance(lsb_depth, int) or not 1 <= lsb_depth <= 8:
        raise ValueError("lsb_depth must be an integer from 1 to 8")

    with Image.open(stego_path) as source:
        if source.format != "PNG":
            raise SerializationFormatError("only PNG stego images are supported")
        image = source.copy()
        image.load()

    width, height = image.size
    pixels = image.load()

    # --- 1. locate + read the fixed-size locator header ---
    header_start = resolve_header_start_channel(width, height, lsb_depth, start_secret, media_id)
    header_bit_len = header_length_bytes() * 8
    header_bytes = _extract_bytes(pixels, width, header_start, header_bit_len, lsb_depth)

    if header_bytes[: len(HEADER_MAGIC)] != HEADER_MAGIC:
        raise LocatorNotFoundError("locator header magic mismatch - no payload found")
    framed_length = int.from_bytes(header_bytes[len(HEADER_MAGIC):], "big")
    if framed_length <= 0:
        raise PayloadFrameError("declared framed payload length is not positive")
    if (header_length_bytes() + framed_length) * 8 > image_capacity_bits(width, height, lsb_depth):
        raise PayloadFrameError("declared payload length exceeds image capacity")

    # --- 2. locate + read the framed, signed payload ---
    start_channel = resolve_payload_start_channel(
        width, height, lsb_depth, start_secret, media_id, framed_length
    )
    framed_bytes = _extract_bytes(pixels, width, start_channel, framed_length * 8, lsb_depth)

    if framed_bytes[: len(FRAME_MAGIC)] != FRAME_MAGIC:
        raise PayloadFrameError("frame magic mismatch - payload is corrupted or absent")
    declared_len = int.from_bytes(
        framed_bytes[len(FRAME_MAGIC): len(FRAME_MAGIC) + _LENGTH_BYTES], "big"
    )
    envelope_bytes = framed_bytes[len(FRAME_MAGIC) + _LENGTH_BYTES:]
    if len(envelope_bytes) != declared_len:
        raise PayloadFrameError("truncated or malformed payload envelope")

    # --- 3. verify signature and parse payload (Person 5) ---
    payload = parse_and_verify(envelope_bytes, public_key_pem)

    # --- 4. FR9: recompute the same stable hash used by the encoder.
    actual_hash = stable_image_hash(stego_path, lsb_depth).hex()
    hash_matches = hmac.compare_digest(actual_hash, payload.media_hash)

    return payload, hash_matches


def _extract_bytes(pixels, width: int, start_channel: int, num_bits: int, lsb_depth: int) -> bytes:
    """Extract ``num_bits`` starting at ``start_channel``, undoing encoder.py's
    MSB-first packing and last-channel left-shift padding exactly."""
    bits: list[int] = []
    bit_index = 0
    channel_index = start_channel
    mask = (1 << lsb_depth) - 1

    while bit_index < num_bits:
        remaining = num_bits - bit_index
        take = min(lsb_depth, remaining)
        x, y, channel = _channel_position(channel_index, width)
        value = pixels[x, y][channel] & mask
        if take < lsb_depth:
            value >>= (lsb_depth - take)  # undo the left-shift padding on a partial chunk
        for i in range(take - 1, -1, -1):
            bits.append((value >> i) & 1)
        bit_index += take
        channel_index += 1

    return _bits_to_bytes(bits)


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)
