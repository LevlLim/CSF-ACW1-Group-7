"""WAV + FLAC support for the Audio tab.

The team's audio LSB code reads and writes 16-bit PCM WAV. FLAC is a WAV
"zipped" losslessly: every sample comes back bit-exact. So a FLAC cover is
converted to WAV, processed by the unchanged audio code, and — if the user
saves as .flac — converted back.

Lossy formats (MP3, AAC...) are never accepted: their compression changes the
low bits the payload lives in. The format is detected from the file's content,
not its extension, so an MP3 renamed to .flac is still rejected.
"""

from __future__ import annotations

from pathlib import Path

from audio_stego.common import AudioStegoError
from video_stego.video_processing import VideoStegoError, extract_audio, wav_to_flac

_WAV_MAGIC = b"RIFF"
_FLAC_MAGIC = b"fLaC"


def is_flac(path: str | Path) -> bool:
    """True for a real FLAC file, False for a real WAV file; raises for anything else."""
    try:
        with open(path, "rb") as file:
            magic = file.read(4)
    except OSError as exc:
        raise AudioStegoError(f"Cannot read audio file: {exc}") from exc

    if magic == _FLAC_MAGIC:
        return True
    if magic == _WAV_MAGIC:
        return False
    raise AudioStegoError(
        "Only WAV and FLAC audio are supported (lossy formats like MP3 would destroy the hidden data)"
    )


def to_wav(path: str | Path, wav_out: Path) -> Path:
    """Return a WAV version of the audio.

    A WAV is returned as-is. A FLAC is converted into ``wav_out`` (normally
    inside a temporary folder the caller cleans up) and that path is returned.
    """
    if not is_flac(path):
        return Path(path)
    try:
        extract_audio(path, wav_out)
    except VideoStegoError as exc:
        raise AudioStegoError(f"Could not read FLAC file: {exc}") from exc
    return wav_out


def wants_flac(path: str | Path) -> bool:
    """Whether the user chose to save the output as FLAC (by its extension)."""
    return Path(path).suffix.lower() == ".flac"


def save_wav_as_flac(wav_path: Path, flac_path: str | Path) -> None:
    try:
        wav_to_flac(wav_path, flac_path)
    except VideoStegoError as exc:
        raise AudioStegoError(f"Could not save FLAC file: {exc}") from exc
