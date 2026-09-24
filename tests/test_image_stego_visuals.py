"""Tests for the image LSB visual diagnostics."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from PIL import Image

from image_stego_visuals import build_visuals, resize_sparse_change_map


class ImageStegoVisualTests(unittest.TestCase):
    def test_bit_plane_map_scales_only_selected_low_bits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            Image.new("RGB", (1, 1), (0, 0b01000010, 0)).save(cover)
            Image.new("RGB", (1, 1), (0b10100111, 0b01000011, 0)).save(stego)

            visuals = build_visuals(cover, stego, lsb_depth=2)

        self.assertEqual(visuals.bit_plane_map.getpixel((0, 0)), (255, 85, 0))

    def test_heat_map_marks_changed_rgb_channels_and_not_unchanged_pixels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            Image.new("RGB", (2, 1), (32, 64, 96)).save(cover)
            changed = Image.new("RGB", (2, 1), (32, 64, 96))
            changed.putpixel((1, 0), (35, 64, 97))
            changed.save(stego)

            visuals = build_visuals(cover, stego, lsb_depth=2)

        self.assertEqual(visuals.heat_map.getpixel((0, 0)), (0, 0, 0))
        self.assertNotEqual(visuals.heat_map.getpixel((1, 0)), (0, 0, 0))
        self.assertEqual(visuals.changed_pixels, 1)
        self.assertEqual(visuals.changed_channels, 2)

    def test_heat_map_keeps_a_single_one_bit_change_in_a_display_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            Image.new("RGB", (80, 80), (100, 100, 100)).save(cover)
            changed = Image.new("RGB", (80, 80), (100, 100, 100))
            changed.putpixel((40, 40), (101, 100, 100))
            changed.save(stego)

            visuals = build_visuals(cover, stego, lsb_depth=1)

        self.assertTrue(any(pixel != (0, 0, 0) for pixel in visuals.heat_map.getdata()))

    def test_rejects_mismatched_image_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            Image.new("RGB", (1, 1)).save(cover)
            Image.new("RGB", (2, 1)).save(stego)

            with self.assertRaises(ValueError):
                build_visuals(cover, stego, lsb_depth=1)

    def test_sparse_preview_preserves_a_one_pixel_change_when_downscaled(self) -> None:
        change_map = Image.new("RGB", (100, 100), (0, 0, 0))
        change_map.putpixel((50, 50), (255, 0, 0))

        preview = resize_sparse_change_map(change_map, (10, 10))

        self.assertTrue(any(pixel != (0, 0, 0) for pixel in preview.getdata()))


if __name__ == "__main__":
    unittest.main()
