"""Create explainable visual diagnostics from a cover/stego PNG pair.

The diagnostics deliberately use only the RGB channels.  Alpha is not a
carrier in this project and including it would make an unchanged transparent
image appear to have been modified.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from pathlib import Path

from PIL import Image, ImageChops, ImageFilter


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

    The change map displays absolute differences between selected cover and
    stego LSB values, scaled to the full 0--255 range. It therefore shows
    only values changed by embedding, not the cover image's natural LSB noise.

    The heat map groups local changed pixels into small blocks.
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


def resize_sparse_change_map(image: Image.Image, size: tuple[int, int]) -> Image.Image:
    """Resize an exact change map without losing one-pixel changes.

    A normal thumbnail can skip a one-pixel-wide carrier region altogether.
    This display-only helper first expands bright change pixels just enough to
    survive downscaling, then uses nearest-neighbour sampling. The original
    map and its exact values are not modified.
    """
    target_width, target_height = size
    if target_width <= 0 or target_height <= 0:
        raise ValueError("preview dimensions must be positive")
    if target_width >= image.width and target_height >= image.height:
        return image.resize(size, Image.Resampling.NEAREST)

    shrink_factor = max(image.width / target_width, image.height / target_height)
    kernel_size = max(3, 2 * ceil(shrink_factor) + 1)
    expanded = image.filter(ImageFilter.MaxFilter(kernel_size))
    return expanded.resize(size, Image.Resampling.NEAREST)


def _build_visuals_from_images(
    cover: Image.Image, stego: Image.Image, lsb_depth: int
) -> ImageStegoVisuals:
    """Build diagnostics from already-normalised RGB images (test helper)."""
    mask = (1 << lsb_depth) - 1
    lsb_lut = [value & mask for value in range(256)] * 3
    scale_lut = [round(value * 255 / mask) for value in range(256)] * 3
    cover_lsb = cover.point(lsb_lut)
    stego_lsb = stego.point(lsb_lut)
    bit_plane_map = ImageChops.difference(cover_lsb, stego_lsb).point(scale_lut)

    full_difference = ImageChops.difference(cover, stego)
    red_difference, green_difference, blue_difference = full_difference.split()
    changed_channels = sum(
        sum(channel.histogram()[1:])
        for channel in (red_difference, green_difference, blue_difference)
    )
    changed_pixel_mask = ImageChops.lighter(ImageChops.lighter(red_difference, green_difference), blue_difference)
    changed_pixels = sum(changed_pixel_mask.histogram()[1:])

    # Heat-map generation runs on compact diagnostic blocks. Pillow performs
    # these image operations in optimized native code, keeping the GUI
    # responsive even when the cover itself is high resolution.
    block_size = max(1, min(12, min(cover.size) // 40))
    blocks_wide = (cover.width + block_size - 1) // block_size
    blocks_high = (cover.height + block_size - 1) // block_size
    # Convert every changed pixel to full brightness *before* block averaging.
    # A one-value RGB LSB difference would otherwise round down to zero when
    # averaged into a larger block, producing an all-black heat map.
    binary_change_mask = changed_pixel_mask.point([0] + [255] * 255)
    density = binary_change_mask.resize((blocks_wide, blocks_high), Image.Resampling.BOX)
    density_histogram = density.histogram()
    peak_density = next(
        (value for value in range(255, -1, -1) if density_histogram[value]),
        0,
    )
    intensity_lut = [round(value * 255 / peak_density) if peak_density else 0 for value in range(256)]
    intensity = density.point(intensity_lut)
    heat_map = Image.merge(
        "RGB",
        (
            intensity.point([min(255, value * 2) for value in range(256)]),
            intensity.point([max(0, value * 2 - 255) for value in range(256)]),
            Image.new("L", intensity.size),
        ),
    )

    return ImageStegoVisuals(
        bit_plane_map=bit_plane_map,
        heat_map=heat_map,
        changed_pixels=changed_pixels,
        changed_channels=changed_channels,
    )


def _validate_lsb_depth(lsb_depth: int) -> None:
    if not isinstance(lsb_depth, int) or not 1 <= lsb_depth <= 8:
        raise ValueError("lsb_depth must be an integer from 1 to 8")
