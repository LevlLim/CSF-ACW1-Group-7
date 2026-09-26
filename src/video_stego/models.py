from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class VideoEncodeResult:
    """Non-secret details for the GUI and the diagnostics visuals.

    Timeline position in seconds = sample index / (sample_rate * channels).
    """

    output_path: Path
    lsb_depth: int
    capacity_bytes: int
    payload_bytes: int
    header_start_sample: int
    payload_start_sample: int
    carriers_used: int
    sample_rate: int
    channels: int
    video_hash_hex: str
