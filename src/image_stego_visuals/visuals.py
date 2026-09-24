"""Create explainable visual diagnostics from a cover/stego PNG pair.

The diagnostics deliberately use only the RGB channels.  Alpha is not a
carrier in this project and including it would make an unchanged transparent
image appear to have been modified.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from PIL import Image


@dataclass(frozen=True, slots=True)
class ImageStegoVisuals:
    """Display-ready visual evidence for one image embedding operation."""

    bit_plane_map: Image.Image
    heat_map: Image.Image
    changed_pixels: int
    changed_channels: int


def build_visuals(
    cover_path: str | Path,
    stego_path: str | Path,
    lsb_depth: int,
) -> ImageStegoVisuals:
    """Build a selected-LSB map and a cover-versus-stego heat map.

    The bit-plane change map XORs the selected low bits in the cover and stego
    image, then scales them to the full 0--255 range.  It exposes only the
    LSB noise introduced by embedding rather than the cover image's naturally
    noisy low bits.

    The heat map aggregates changed RGB channels into small local blocks.
    It is a relative density view: black means no changes in that block,
    while red/yellow mark progressively denser embedding activity.
    """
    _validate_lsb_depth(lsb_depth)
    with Image.open(cover_path) as cover_source:
        cover = cover_source.convert("RGB")
    with Image.open(stego_path) as stego_source:
        stego = stego_source.convert("RGB")

    if cover.size != stego.size:
        raise ValueError("cover and stego images must have identical dimensions")

    return _build_visuals_from_images(cover, stego, lsb_depth)


def _build_visuals_from_images(
    cover: Image.Image, stego: Image.Image, lsb_depth: int
) -> ImageStegoVisuals:
    """Build diagnostics from already-normalised RGB images (test helper)."""
    mask = (1 << lsb_depth) - 1
    bit_plane_map = Image.new("RGB", cover.size)
    heat_map = Image.new("RGB", cover.size)
    changed_pixels = 0
    changed_channels = 0
    block_size = max(1, min(12, min(cover.size) // 40))
    blocks_wide = (cover.width + block_size - 1) // block_size
    blocks_high = (cover.height + block_size - 1) // block_size
    density = [0] * (blocks_wide * blocks_high)

    for y in range(cover.height):
        for x in range(cover.width):
            position = (x, y)
            # The inputs were normalised to RGB in ``build_visuals``.
            cover_pixel = cast(tuple[int, int, int], cover.getpixel(position))
            stego_pixel = cast(tuple[int, int, int], stego.getpixel(position))
            change = 0
            changed_in_pixel = 0
            changed_lsb_channels: list[int] = []
            for channel in range(3):
                lsb_change = (cover_pixel[channel] & mask) ^ (stego_pixel[channel] & mask)
                changed_lsb_channels.append(round(lsb_change * 255 / mask))
                if cover_pixel[channel] != stego_pixel[channel]:
                    changed_in_pixel += 1
                    change += abs(stego_pixel[channel] - cover_pixel[channel])
            bit_plane_map.putpixel(position, tuple(changed_lsb_channels))

            if changed_in_pixel:
                changed_pixels += 1
                changed_channels += changed_in_pixel
                block_x = x // block_size
                block_y = y // block_size
                density[block_y * blocks_wide + block_x] += change

    peak_density = max(density, default=0)
    for block_y in range(blocks_high):
        for block_x in range(blocks_wide):
            value = density[block_y * blocks_wide + block_x]
            intensity = round(value * 255 / peak_density) if peak_density else 0
            heat_colour = (min(255, intensity * 2), max(0, intensity * 2 - 255), 0)
            left = block_x * block_size
            top = block_y * block_size
            for y in range(top, min(top + block_size, cover.height)):
                for x in range(left, min(left + block_size, cover.width)):
                    heat_map.putpixel((x, y), heat_colour)

    return ImageStegoVisuals(
        bit_plane_map=bit_plane_map,
        heat_map=heat_map,
        changed_pixels=changed_pixels,
        changed_channels=changed_channels,
    )


def _validate_lsb_depth(lsb_depth: int) -> None:
    if not isinstance(lsb_depth, int) or not 1 <= lsb_depth <= 8:
        raise ValueError("lsb_depth must be an integer from 1 to 8")
