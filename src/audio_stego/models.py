from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class WavData:
    samples: tuple[int, ...]
    channels: int
    sample_width: int
    frame_rate: int
    frame_count: int


@dataclass(frozen=True, slots=True)
class AudioEncodeResult:
    output_path: Path
    start_location: int
    lsb_depth: int
    payload_bytes: int
    carriers_used: int
    capacity: int