"""Tests for the PNG image LSB encoder contract."""

from __future__ import annotations

import tempfile
import unittest
from math import ceil
from pathlib import Path

from PIL import Image

from image_encoder import (
    FRAME_MAGIC,
    HEADER_MAGIC,
    check_capacity,
    encode_image_file,
    frame_payload,
    header_length_bytes,
    resolve_header_start_channel,
    resolve_payload_start_channel,
)


class ImageEncoderTests(unittest.TestCase):
    def test_capacity_uses_rgb_channels_and_selected_lsb_depth(self) -> None:
        self.assertTrue(check_capacity(10, 10, b"small", 1))
        self.assertFalse(check_capacity(1, 1, b"small", 1))
        with self.assertRaises(ValueError):
            check_capacity(10, 10, b"x", 0)

    def test_frame_payload_adds_magic_and_big_endian_length(self) -> None:
        framed = frame_payload(b"abc")
        self.assertEqual(framed[: len(FRAME_MAGIC)], FRAME_MAGIC)
        self.assertEqual(int.from_bytes(framed[len(FRAME_MAGIC) : len(FRAME_MAGIC) + 4], "big"), 3)
        self.assertEqual(framed[-3:], b"abc")

    def test_encode_png_embeds_payload_and_preserves_alpha(self) -> None:
        secret = b"s" * 32
        media_id = "image-001"
        payload = b"signed-envelope"
        lsb_depth = 2

        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            Image.new("RGBA", (12, 12), (120, 80, 40, 77)).save(cover)

            result = encode_image_file(
                cover,
                stego,
                payload,
                lsb_depth=lsb_depth,
                start_secret=secret,
                media_id=media_id,
            )

            self.assertEqual(result.stego_path, stego)
            self.assertEqual(result.embedded_bits, (len(HEADER_MAGIC) + 4 + len(frame_payload(payload))) * 8)
            self.assertGreater(result.changed_channel_values, 0)

            with Image.open(stego) as image:
                self.assertEqual(image.mode, "RGBA")
                self.assertEqual(image.getpixel((0, 0))[3], 77)
                header = _extract_framed_bytes(
                    image,
                    lsb_depth,
                    resolve_header_start_channel(image.width, image.height, lsb_depth, secret, media_id),
                    header_length_bytes(),
                )
                self.assertEqual(header[: len(HEADER_MAGIC)], HEADER_MAGIC)
                framed_length = int.from_bytes(header[len(HEADER_MAGIC) :], "big")
                payload_start = resolve_payload_start_channel(
                    image.width,
                    image.height,
                    lsb_depth,
                    secret,
                    media_id,
                    framed_length,
                )
                extracted = _extract_framed_bytes(
                    image,
                    lsb_depth,
                    payload_start,
                    framed_length,
                )
            self.assertEqual(extracted, frame_payload(payload))


def _extract_framed_bytes(image: Image.Image, lsb_depth: int, start_channel: int, byte_count: int) -> bytes:
    bits: list[int] = []
    mask = (1 << lsb_depth) - 1
    channels_needed = ceil(byte_count * 8 / lsb_depth)
    pixels = image.load()

    for channel_index in range(start_channel, start_channel + channels_needed):
        pixel_index, channel = divmod(channel_index, 3)
        y, x = divmod(pixel_index, image.width)
        value = pixels[x, y][channel] & mask
        for bit in range(lsb_depth - 1, -1, -1):
            bits.append((value >> bit) & 1)

    output = bytearray()
    for offset in range(0, byte_count * 8, 8):
        byte = 0
        for bit in bits[offset : offset + 8]:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)


if __name__ == "__main__":
    unittest.main()
