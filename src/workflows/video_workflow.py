"""Video workflow: wires crypto_payload + video_stego/video_decoder together.

No GUI toolkit here, so the GUI, a demo script, or tests can all call it the same way.
Mirrors audio_workflow.py's shape.
"""

from __future__ import annotations

import wave
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image

from audio_stego.common import carrier_count_for_bytes, frame_payload
from audio_stego.locations import header_length_bytes
from audio_stego_visuals import AudioStegoVisuals, build_visuals
from crypto_payload import build_payload, sign_payload
from video_decoder import VideoDecodeResult, decode_video_file
from video_stego import VideoEncodeResult, VideoStegoError, encode_video_file
from video_stego.common import MAX_DURATION_SECONDS, require_video_and_audio, video_metadata
from video_stego.video_processing import extract_audio, extract_thumbnail, probe_streams


@dataclass(frozen=True, slots=True)
class VideoInfo:
    """What the GUI shows about a cover video, read once when it is selected."""

    duration_seconds: float
    sample_rate: int
    channels: int
    sample_count: int
    stream_kinds: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VideoCapacityStatus:
    """Whether a signed envelope fits in a cover video's audio at a given LSB depth."""

    fits: bool
    needed_bytes: int
    capacity_bytes: int


def inspect_video(cover_path: Path) -> VideoInfo:
    """Read the cover's layout and audio format (without loading every sample).

    Raises VideoStegoError if the file has no video/audio, can't be read, or
    is longer than MAX_DURATION_SECONDS.
    """
    streams = probe_streams(cover_path)
    require_video_and_audio(streams)

    with TemporaryDirectory() as temp_name:
        wav_path = Path(temp_name) / "audio.wav"
        extract_audio(cover_path, wav_path, max_seconds=MAX_DURATION_SECONDS + 1)
        # Only the WAV header is read here — loading millions of samples just
        # to show the duration would make selecting a file slow.
        with wave.open(str(wav_path), "rb") as wav_file:
            channels = wav_file.getnchannels()
            sample_rate = wav_file.getframerate()
            frame_count = wav_file.getnframes()

    duration = frame_count / sample_rate if sample_rate else 0.0
    if duration > MAX_DURATION_SECONDS:
        raise VideoStegoError(
            f"Video is longer than the {MAX_DURATION_SECONDS}s maximum — trim it first"
        )
    return VideoInfo(
        duration_seconds=duration,
        sample_rate=sample_rate,
        channels=channels,
        sample_count=frame_count * channels,
        stream_kinds=tuple(stream.kind for stream in streams),
    )


def check_video_capacity(
    info: VideoInfo, media_id: str, private_key_pem: bytes, lsb_depth: int, note: str = ""
) -> VideoCapacityStatus:
    """Report whether the payload fits, without touching the video (fast enough per keypress).

    The signed envelope's size doesn't depend on the hash's value (always
    32 bytes), so a placeholder hash gives the exact size of the real payload.
    """
    metadata = video_metadata(lsb_depth, info.sample_rate, info.channels, info.sample_count, note)
    envelope = sign_payload(build_payload(media_id, bytes(32), metadata), private_key_pem)
    framed_length = len(frame_payload(envelope))

    # Same carrier maths as the encoder, so "Fits" here means the encoder will accept it.
    carriers_needed = (
        carrier_count_for_bytes(header_length_bytes(), lsb_depth)
        + carrier_count_for_bytes(framed_length, lsb_depth)
    )
    return VideoCapacityStatus(
        fits=carriers_needed <= info.sample_count,
        needed_bytes=header_length_bytes() + framed_length,
        capacity_bytes=info.sample_count * lsb_depth // 8,
    )


def video_thumbnail(video_path: Path) -> Image.Image:
    """First frame of the video, for the GUI's cover-vs-stego comparison."""
    with TemporaryDirectory() as temp_name:
        png_path = Path(temp_name) / "thumbnail.png"
        extract_thumbnail(video_path, png_path)
        with Image.open(png_path) as image:
            return image.copy()  # copy: the temp file is deleted on return


def build_video_visuals(cover_path: Path, stego_path: Path, lsb_depth: int) -> AudioStegoVisuals:
    """Reuse the team's WAV diagnostics on the audio tracks of cover and stego video."""
    with TemporaryDirectory() as temp_name:
        cover_wav = Path(temp_name) / "cover.wav"
        stego_wav = Path(temp_name) / "stego.wav"
        extract_audio(cover_path, cover_wav, max_seconds=MAX_DURATION_SECONDS + 1)
        extract_audio(stego_path, stego_wav, max_seconds=MAX_DURATION_SECONDS + 1)
        return build_visuals(cover_wav, stego_wav, lsb_depth)


def encode_video(
    cover_path: Path,
    stego_path: Path | str,
    media_id: str,
    private_key_pem: bytes,
    start_secret: bytes,
    lsb_depth: int,
    note: str = "",
) -> VideoEncodeResult:
    return encode_video_file(
        input_path=cover_path,
        output_path=stego_path,
        media_id=media_id,
        private_key_pem=private_key_pem,
        start_secret=start_secret,
        lsb_depth=lsb_depth,
        note=note,
    )


def decode_video(
    stego_path: Path | str,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> VideoDecodeResult:
    """Extract and verify a signed payload from a stego video."""
    return decode_video_file(
        stego_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )
