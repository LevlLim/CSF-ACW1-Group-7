"""All ffmpeg calls live here, nowhere else (video cover object + the Audio tab's FLAC support).

Uses the ffmpeg binary bundled by imageio-ffmpeg, so no system install is needed.
Every function either returns data or raises VideoStegoError — no printing;
the GUI decides what to show.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import imageio_ffmpeg

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
_TIMEOUT_SECONDS = 120


class VideoStegoError(Exception):
    """Base error for video steganography."""


@dataclass(frozen=True, slots=True)
class StreamInfo:
    """One stream inside a video container, as reported by ffmpeg's streamhash."""

    index: int
    kind: str  # "v" video, "a" audio, "s" subtitle, "d" data
    sha256: bytes  # 32 raw bytes


def _run_ffmpeg(args: list[str]) -> bytes:
    """Run ffmpeg safely and return its stdout.

    - List of args and no shell=True: filenames can never run as commands.
    - -nostdin + timeout: a malformed file can't hang the app.
    - Non-zero exit raises: never continue with a half-written file.
    """
    cmd = [FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin", "-y", *args]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as exc:
        raise VideoStegoError("ffmpeg timed out") from exc
    if result.returncode != 0:
        raise VideoStegoError(result.stderr.decode(errors="replace").strip() or "ffmpeg failed")
    return result.stdout


def _safe_path(path: str | Path) -> str:
    """Absolute path, so a filename like '-i evil.mp4' can't be read as an ffmpeg option."""
    return str(Path(path).resolve())


def probe_streams(video: str | Path) -> list[StreamInfo]:
    """Get info about every stream inside the video.

    For example, an MP4 may contain a video stream and an audio stream.
    FFmpeg calculates a SHA-256 hash for each stream without re-encoding it.

    Unknown stream types are kept so later checks can detect extra tracks.

    Raises:
        VideoStegoError: If ffmpeg cannot read the file or returns invalid output.
    """
    output = _run_ffmpeg([
        "-i", _safe_path(video),
        "-map", "0",
        "-c", "copy",
        "-f", "streamhash",
        "-hash", "sha256",
        "-",
    ])

    # streamhash output is always plain ASCII; anything else means something
    # went wrong, so fail instead of guessing.
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise VideoStegoError("ffmpeg returned non-ASCII streamhash output") from exc

    if not lines:
        raise VideoStegoError("ffmpeg returned no stream hashes")

    return [_parse_streamhash_line(line) for line in lines]


def _parse_streamhash_line(line: str) -> StreamInfo:
    """Parse one line like '0,v,SHA256=<64 hex chars>' into a StreamInfo."""
    parts = line.split(",")
    if len(parts) != 3:
        raise VideoStegoError(f"Invalid streamhash line: {line!r}")

    index_text, kind, hash_text = parts
    if not hash_text.startswith("SHA256="):
        raise VideoStegoError(f"Expected a SHA256= hash in streamhash line: {line!r}")

    try:
        index = int(index_text)
        sha256 = bytes.fromhex(hash_text.removeprefix("SHA256="))
    except ValueError as exc:
        raise VideoStegoError(f"Invalid streamhash line: {line!r}") from exc

    if len(sha256) != 32:
        raise VideoStegoError(f"SHA-256 hash must be 32 bytes: {line!r}")

    return StreamInfo(index=index, kind=kind, sha256=sha256)


def extract_audio(video: str | Path, wav_out: str | Path, max_seconds: float | None = None) -> None:
    """Extract the first audio stream as a 16-bit PCM WAV file.

    The WAV format lets the existing audio steganography code work with
    the video's audio samples.

    max_seconds stops extraction early, so a very long video can't fill the
    disk or memory before its length is checked.
    """
    length_limit = ["-t", str(max_seconds)] if max_seconds is not None else []
    _run_ffmpeg([
        "-i", _safe_path(video),
        "-map", "0:a:0",
        *length_limit,
        "-c:a", "pcm_s16le",
        "-f", "wav",
        _safe_path(wav_out),
    ])


def remux(cover_video: str | Path, stego_wav: str | Path, out: str | Path) -> None:
    """Combine the original video with the stego audio into an MP4.

    The video stream is copied without re-encoding. The stego audio is
    stored as lossless FLAC so the hidden audio samples are preserved.

    FLAC, not ALAC: both are lossless, but Windows' built-in Media Player
    plays ALAC-in-MP4 silently, which made genuine stego videos look broken.
    """
    _run_ffmpeg([
        "-i", _safe_path(cover_video),
        "-i", _safe_path(stego_wav),
        "-map", "0:V:0",
        "-map", "1:a:0",
        "-c:v", "copy",
        "-c:a", "flac",
        "-f", "mp4",
        _safe_path(out),
    ])


def wav_to_flac(wav: str | Path, flac_out: str | Path) -> None:
    """Losslessly compress a WAV into a FLAC file (used by the Audio tab's FLAC support).

    FLAC keeps every sample bit-exact, so hidden LSB data survives.
    """
    _run_ffmpeg([
        "-i", _safe_path(wav),
        "-map", "0:a:0",
        "-c:a", "flac",
        "-f", "flac",
        _safe_path(flac_out),
    ])


def extract_thumbnail(video: str | Path, png_out: str | Path) -> None:
    """Save the first video frame as a PNG image, for the GUI's cover-vs-stego comparison.

    "-update 1" writes exactly one file with the literal name given; without it,
    a name containing "%d" would be treated as an image-sequence pattern.
    """
    _run_ffmpeg([
        "-i", _safe_path(video),
        "-map", "0:V:0",
        "-frames:v", "1",
        "-update", "1",
        "-c:v", "png",
        "-f", "image2",
        _safe_path(png_out),
    ])