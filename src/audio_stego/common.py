from __future__ import annotations

import struct
import wave
from pathlib import Path
from math import ceil

from .models import WavData


class AudioStegoError(Exception):
    """Base error for audio steganography."""


def load_wav_pcm(file_path: str | Path) -> WavData:
    """Load an uncompressed 8-bit or 16-bit PCM WAV file."""

    try:
        with wave.open(str(file_path), "rb") as wav_file:

            if wav_file.getcomptype() != "NONE":
                raise AudioStegoError(
                    "Only uncompressed PCM WAV files are supported"
                )

            channels = wav_file.getnchannels()
            sample_width = wav_file.getsampwidth()
            frame_rate = wav_file.getframerate()
            frame_count = wav_file.getnframes()

            raw_frames = wav_file.readframes(frame_count)

    except (wave.Error, OSError) as exc:
        raise AudioStegoError(
            f"Unable to read WAV file: {exc}"
        ) from exc

    if sample_width == 1:
        # 8-bit WAV is unsigned.
        samples = tuple(raw_frames)

    elif sample_width == 2:
        # 16-bit PCM is signed little-endian.
        sample_count = len(raw_frames) // 2

        samples = struct.unpack(
            f"<{sample_count}h",
            raw_frames
        )

    else:
        raise AudioStegoError(
            "Only 8-bit and 16-bit PCM are currently supported"
        )

    return WavData(
        samples=tuple(samples),
        channels=channels,
        sample_width=sample_width,
        frame_rate=frame_rate,
        frame_count=frame_count,
    )

MAGIC = b"CSF7"
LENGTH_BYTES = 4
HEADER_BYTES = len(MAGIC) + LENGTH_BYTES


def frame_payload(payload: bytes) -> bytes:
    """Add a magic header and payload length."""

    if not payload:
        raise AudioStegoError(
            "Payload cannot be empty"
        )

    length = len(payload).to_bytes(
        LENGTH_BYTES,
        byteorder="big"
    )

    return MAGIC + length + payload

#Creating the stable audio bytes representation for hashing and comparison
def stable_audio_bytes(
    wav: WavData,
    lsb_depth: int
) -> bytes:
    """Create the stable PCM representation used for hashing."""

    if not 1 <= lsb_depth <= 8:
        raise ValueError(
            "lsb_depth must be between 1 and 8"
        )

    mask = (1 << lsb_depth) - 1

    cleaned_samples = tuple(
        sample & ~mask
        for sample in wav.samples
    )

    if wav.sample_width == 1:
        return bytes(
            sample & 0xFF
            for sample in cleaned_samples
        )

    if wav.sample_width == 2:
        return struct.pack(
            f"<{len(cleaned_samples)}h",
            *cleaned_samples
        )

    raise AudioStegoError(
        "Unsupported sample width"
    )

#convert payload bytes to bits
def bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a MSB-first list of bits."""

    bits = []

    for byte in data:
        for shift in range(7, -1, -1):
            bits.append(
                (byte >> shift) & 1
            )

    return bits

def save_wav_pcm(
    output_path: str | Path,
    wav: WavData,
    samples: tuple[int, ...],
) -> None:
    """Save PCM samples while preserving WAV properties."""

    if wav.sample_width == 1:
        raw_frames = bytes(
            sample & 0xFF
            for sample in samples
        )

    elif wav.sample_width == 2:
        raw_frames = struct.pack(
            f"<{len(samples)}h",
            *samples
        )

    else:
        raise AudioStegoError(
            "Unsupported sample width"
        )

    with wave.open(
        str(output_path),
        "wb"
    ) as output:

        output.setnchannels(
            wav.channels
        )

        output.setsampwidth(
            wav.sample_width
        )

        output.setframerate(
            wav.frame_rate
        )

        output.writeframes(
            raw_frames
        )

def carrier_count_for_bytes(
    byte_count: int,
    lsb_depth: int
) -> int:
    """
    Calculate how many PCM samples are required
    to embed byte_count bytes.
    """

    if not 1 <= lsb_depth <= 8:
        raise ValueError(
            "lsb_depth must be between 1 and 8"
        )

    total_bits = byte_count * 8

    return ceil(total_bits / lsb_depth)


def audio_capacity_bytes(
    sample_count: int,
    lsb_depth: int
) -> int:
    """
    Calculate the maximum number of whole bytes
    that can be embedded in the audio.
    """

    if not 1 <= lsb_depth <= 8:
        raise ValueError(
            "lsb_depth must be between 1 and 8"
        )

    total_bits = sample_count * lsb_depth

    return total_bits // 8