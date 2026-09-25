from __future__ import annotations

import base64
import json
from math import ceil
from pathlib import Path

from PIL import Image

from crypto_payload import generate_ed25519_keypair
from image_decoder import decode_image_file
from image_encoder import (
    FRAME_MAGIC,
    HEADER_MAGIC,
    frame_payload,
    header_length_bytes,
    resolve_header_start_channel,
    resolve_payload_start_channel,
)

from .models import AttackSimulationResult

_RGB_CHANNELS = 3
_LENGTH_BYTES = 4

# --- helpers -----------------------------------------------------------
# _channel_position, _extract_bytes and _bits_to_bytes mirror image_decoder's
# private helpers of the same names exactly (row-major pixels, 3 RGB
# channels per pixel, MSB-first bit packing) — duplicated locally rather
# than imported, matching the convention image_decoder.py itself already
# uses for image_encoder's private _channel_position.

def _channel_position(channel_index: int, width: int) -> tuple[int, int, int]:
    pixel_index, channel = divmod(channel_index, _RGB_CHANNELS)
    y, x = divmod(pixel_index, width)
    return x, y, channel

def _channels_for_bytes(byte_count: int, lsb_depth: int) -> int:
    return ceil(byte_count * 8 / lsb_depth)

def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits

def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

def _extract_bytes(pixels, width: int, start_channel: int, num_bits: int, lsb_depth: int) -> bytes:
    """Extract num_bits starting at start_channel, undoing encoder.py's
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
            value >>= (lsb_depth - take)
        for i in range(take - 1, -1, -1):
            bits.append((value >> i) & 1)
        bit_index += take
        channel_index += 1

    return _bits_to_bytes(bits)

def _embed_bytes(pixels, width: int, start_channel: int, data: bytes, lsb_depth: int) -> None:
    """Write data into pixels starting at start_channel, using the same
    MSB-first packing and last-channel left-shift padding image_encoder's
    private _embed_bits/_bits_to_value use. Used only by the payload
    corruption attack, to overwrite an already-embedded region in place
    without needing image_encoder's full encode_image_file re-embed."""
    bits = _bytes_to_bits(data)
    keep_mask = (0xFF << lsb_depth) & 0xFF
    channel_index = start_channel
    bit_index = 0

    while bit_index < len(bits):
        chunk = bits[bit_index : bit_index + lsb_depth]
        take = len(chunk)
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        if take < lsb_depth:
            value <<= (lsb_depth - take)

        x, y, channel = _channel_position(channel_index, width)
        pixel = list(pixels[x, y])
        pixel[channel] = (pixel[channel] & keep_mask) | value
        pixels[x, y] = tuple(pixel)

        bit_index += lsb_depth
        channel_index += 1

def _remove_frame(framed: bytes) -> bytes:
    if framed[: len(FRAME_MAGIC)] != FRAME_MAGIC:
        raise ValueError("Framed payload magic missing")
    declared_length = int.from_bytes(framed[len(FRAME_MAGIC) : len(FRAME_MAGIC) + _LENGTH_BYTES], "big")
    envelope = framed[len(FRAME_MAGIC) + _LENGTH_BYTES :]
    if len(envelope) != declared_length:
        raise ValueError("Payload length mismatch")
    return envelope

def _canonical_json_bytes(value: object) -> bytes:
    """Matches crypto_payload.core's canonical JSON formatting, so a
    same-length field substitution keeps the overall envelope's byte length
    unchanged and the modified payload can be re-embedded at the same
    location without disturbing the locator header."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def _read_layout(pixels, width: int, height: int, lsb_depth: int, start_secret: bytes, media_id: str) -> dict[str, int]:
    """Re-derive where the locator header and payload live, exactly as
    image_decoder.decode_image_file does internally."""
    header_start = resolve_header_start_channel(width, height, lsb_depth, start_secret, media_id)
    header_bytes = _extract_bytes(pixels, width, header_start, header_length_bytes() * 8, lsb_depth)

    if header_bytes[: len(HEADER_MAGIC)] != HEADER_MAGIC:
        raise ValueError("Could not find locator header")

    framed_length = int.from_bytes(header_bytes[len(HEADER_MAGIC) :], "big")
    if framed_length <= 0:
        raise ValueError("Invalid framed payload length")

    payload_start = resolve_payload_start_channel(width, height, lsb_depth, start_secret, media_id, framed_length)

    return {
        "header_start": header_start,
        "header_channels": _channels_for_bytes(header_length_bytes(), lsb_depth),
        "payload_start": payload_start,
        "payload_channels": _channels_for_bytes(framed_length, lsb_depth),
        "framed_length": framed_length,
    }

def _find_unprotected_channel(capacity: int, layout: dict[str, int]) -> int:
    """Find an RGB channel slot outside both the header and payload
    regions, so tampering it doesn't corrupt the hidden data itself — only
    the cover image's own content, which is exactly what FR9's hash
    recheck is meant to catch."""
    blocked_regions = (
        (layout["header_start"], layout["header_start"] + layout["header_channels"]),
        (layout["payload_start"], layout["payload_start"] + layout["payload_channels"]),
    )
    for channel_index in range(capacity):
        if not any(start <= channel_index < end for start, end in blocked_regions):
            return channel_index
    raise ValueError("No free image channel could be found")

def _flip_channel_bit(value: int, bit_position: int) -> int:
    """Flip one bit of an 8-bit RGB channel value. Unlike audio's 16-bit
    signed PCM samples, image channel values are plain unsigned bytes, so
    no sign-bit correction is needed."""
    return value ^ (1 << bit_position)

def _open_rgb(stego_path: str | Path):
    with Image.open(stego_path) as source:
        if source.format != "PNG":
            raise ValueError("only PNG stego images are supported")
        image = source.copy()
        image.load()
    return image

# --- attacks -------------------------------------------------------------

def simulate_image_tampering(
    stego_path: str | Path,
    output_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> AttackSimulationResult:
    """Modify one real image bit outside the hidden regions, while leaving
    the embedded payload and signature untouched."""
    image = _open_rgb(stego_path)
    width, height = image.size
    pixels = image.load()
    capacity = width * height * _RGB_CHANNELS

    layout = _read_layout(pixels, width, height, lsb_depth, start_secret, media_id)

    # First bit ABOVE the LSB embedding region.
    bit_to_flip = lsb_depth
    if bit_to_flip >= 8:
        raise ValueError("No non-LSB image bit is available to flip")

    channel_index = _find_unprotected_channel(capacity, layout)
    x, y, channel = _channel_position(channel_index, width)
    pixel = list(pixels[x, y])
    pixel[channel] = _flip_channel_bit(pixel[channel], bit_to_flip)
    pixels[x, y] = tuple(pixel)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path, format="PNG")

    verification = decode_image_file(
        output_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )

    return AttackSimulationResult(
        attack_name="Image tampering",
        verdict=verification.verdict,
        output_path=Path(output_path),
        details=(
            f"Flipped image bit {bit_to_flip} at channel index {channel_index} "
            f"(pixel {(x, y)}, channel {channel})."
        ),
    )

def simulate_image_wrong_key_verification(
    stego_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
) -> AttackSimulationResult:
    """Verify a valid stego PNG using an unrelated Ed25519 public key."""
    _, wrong_public_key = generate_ed25519_keypair()

    verification = decode_image_file(
        stego_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=wrong_public_key,
    )

    return AttackSimulationResult(
        attack_name="Wrong-key verification",
        verdict=verification.verdict,
        output_path=None,
        details="Verified the valid stego PNG using an unrelated public key.",
    )

def simulate_image_payload_corruption(
    stego_path: str | Path,
    output_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> AttackSimulationResult:
    """Change one character of the embedded payload's media_id, keeping the
    byte length identical, and re-embed it WITHOUT re-signing — the
    signature that's still there was computed over the original bytes, so
    it should no longer verify."""
    image = _open_rgb(stego_path)
    width, height = image.size
    pixels = image.load()

    layout = _read_layout(pixels, width, height, lsb_depth, start_secret, media_id)

    framed = _extract_bytes(pixels, width, layout["payload_start"], layout["framed_length"] * 8, lsb_depth)
    envelope_bytes = _remove_frame(framed)

    try:
        envelope = json.loads(envelope_bytes.decode("utf-8"))
        payload_bytes = base64.urlsafe_b64decode(envelope["payload"])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Could not parse embedded signed payload") from exc

    old_media_id = payload.get("media_id")
    if not isinstance(old_media_id, str) or not old_media_id:
        raise ValueError("Payload contains no valid media_id")

    replacement = "X" if old_media_id[0] != "X" else "Y"
    payload["media_id"] = replacement + old_media_id[1:]

    modified_payload_bytes = _canonical_json_bytes(payload)
    if len(modified_payload_bytes) != len(payload_bytes):
        raise ValueError("Payload corruption changed payload length")

    # Replace ONLY the payload, keep the (now stale) signature untouched.
    envelope["payload"] = base64.urlsafe_b64encode(modified_payload_bytes).decode("ascii")
    modified_envelope_bytes = _canonical_json_bytes(envelope)

    modified_framed = frame_payload(modified_envelope_bytes)
    if len(modified_framed) != len(framed):
        raise ValueError("Payload corruption changed framed length")

    _embed_bytes(pixels, width, layout["payload_start"], modified_framed, lsb_depth)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path, format="PNG")

    verification = decode_image_file(
        output_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )

    return AttackSimulationResult(
        attack_name="Payload corruption",
        verdict=verification.verdict,
        output_path=Path(output_path),
        details=(
            f"Changed embedded media_id from {old_media_id!r} to "
            f"{payload['media_id']!r} without re-signing."
        ),
    )

def simulate_image_wrong_start_location(
    stego_path: str | Path,
    *,
    lsb_depth: int,
    media_id: str,
    public_key_pem: bytes,
    wrong_start_secret: bytes = b"attack-simulation-wrong-secret",
) -> AttackSimulationResult:
    """Attempt extraction using the wrong start-location secret."""
    verification = decode_image_file(
        stego_path,
        lsb_depth=lsb_depth,
        start_secret=wrong_start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )

    return AttackSimulationResult(
        attack_name="Wrong start-location extraction",
        verdict=verification.verdict,
        output_path=None,
        details="Attempted extraction using an incorrect start-location secret.",
    )