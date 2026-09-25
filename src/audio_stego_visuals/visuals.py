"""Create display-ready LSB diagnostics from a cover/stego WAV pair."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw

from audio_stego.common import AudioStegoError, load_wav_pcm

_WIDTH = 640
_TIMELINE_HEIGHT = 160


@dataclass(frozen=True, slots=True)
class AudioStegoVisuals:
    """Visual evidence for a WAV LSB embedding operation."""

    lsb_change_map: Image.Image
    density_timeline: Image.Image
    changed_samples: int
    changed_lsb_bits: int


def build_visuals(
    cover_path: str | Path, stego_path: str | Path, lsb_depth: int
) -> AudioStegoVisuals:
    """Build a selected-LSB change map and an embedding-density timeline.

    Both charts group neighbouring PCM samples into horizontal time bins. The
    first chart has one row per selected LSB plane; brighter cells mean that
    bit changed more often in that time range. The second chart normalises
    each bin against the busiest bin, making the embedded region visible even
    when it occupies only a small part of a long WAV.
    """
    _validate_lsb_depth(lsb_depth)
    cover = load_wav_pcm(cover_path)
    stego = load_wav_pcm(stego_path)
    if (
        cover.sample_width != stego.sample_width
        or cover.channels != stego.channels
        or cover.frame_rate != stego.frame_rate
        or len(cover.samples) != len(stego.samples)
    ):
        raise AudioStegoError("cover and stego WAV files must have matching PCM properties")

    mask = (1 << lsb_depth) - 1
    changes = tuple((cover_sample & mask) ^ (stego_sample & mask) for cover_sample, stego_sample in zip(cover.samples, stego.samples))
    changed_samples = sum(change != 0 for change in changes)
    changed_lsb_bits = sum(change.bit_count() for change in changes)
    width = min(_WIDTH, max(1, len(changes)))
    bins = _sample_bins(len(changes), width)

    return AudioStegoVisuals(
        lsb_change_map=_build_lsb_change_map(changes, lsb_depth, bins),
        density_timeline=_build_density_timeline(changes, bins),
        changed_samples=changed_samples,
        changed_lsb_bits=changed_lsb_bits,
    )


def _sample_bins(sample_count: int, width: int) -> tuple[tuple[int, int], ...]:
    return tuple((column * sample_count // width, (column + 1) * sample_count // width) for column in range(width))


def _build_lsb_change_map(
    changes: tuple[int, ...], lsb_depth: int, bins: tuple[tuple[int, int], ...]
) -> Image.Image:
    image_height = max(120, lsb_depth * 20)
    row_height = image_height // lsb_depth
    image = Image.new("RGB", (len(bins), image_height), "#0B1220")
    pixels = image.load()
    assert pixels is not None
    for bit in range(lsb_depth):
        top = (lsb_depth - bit - 1) * row_height
        for column, (start, end) in enumerate(bins):
            sample_count = max(1, end - start)
            intensity = round(sum((change >> bit) & 1 for change in changes[start:end]) * 255 / sample_count)
            colour = (28, intensity, 255) if intensity else (11, 18, 32)
            for y in range(top, top + row_height - 1):
                pixels[column, y] = colour
    return image


def _build_density_timeline(changes: tuple[int, ...], bins: tuple[tuple[int, int], ...]) -> Image.Image:
    image = Image.new("RGB", (len(bins), _TIMELINE_HEIGHT), "#0B1220")
    draw = ImageDraw.Draw(image)
    counts = [sum(change != 0 for change in changes[start:end]) for start, end in bins]
    peak = max(counts, default=0)
    for column, count in enumerate(counts):
        if count == 0 or peak == 0:
            continue
        height = max(1, round(count * (_TIMELINE_HEIGHT - 1) / peak))
        intensity = round(count * 255 / peak)
        draw.line(
            ((column, _TIMELINE_HEIGHT - 1), (column, _TIMELINE_HEIGHT - height)),
            fill=(255, max(48, intensity), 0),
        )
    return image


def _validate_lsb_depth(lsb_depth: int) -> None:
    if not isinstance(lsb_depth, int) or not 1 <= lsb_depth <= 8:
        raise ValueError("lsb_depth must be an integer from 1 to 8")
