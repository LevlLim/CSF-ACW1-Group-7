"""Rules shared by the video encoder AND decoder.

If encode and decode disagree on any of these, a genuine untouched file
would verify as Tampered — so they live in one place, like
audio_stego/common.py does for audio.
"""

from __future__ import annotations

from typing import Any

from audio_stego.models import WavData

from .video_processing import StreamInfo, VideoStegoError

# The existing audio code keeps every sample as a Python int: ~300 MB RAM
# for 60 s of stereo audio, so longer clips could freeze or crash the app.
MAX_DURATION_SECONDS = 60

# Prefixed to the hashed bytes so a video hash can never be confused with
# an image or audio hash, even over the same data.
HASH_DOMAIN = b"CSF-VIDEO-V1"


class VideoTamperedError(VideoStegoError):
    """The file was readable, but it is not what our encoder produced.

    Separate from VideoStegoError so the decoder can report "Tampered"
    instead of "Cannot Verify".
    """


def video_metadata(
    lsb_depth: int, sample_rate: int, channels: int, sample_count: int, note: str = ""
) -> dict[str, Any]:
    """The team-defined metadata signed into every video payload.

    Shared by the encoder and the GUI's capacity check, so the size estimate
    is built from exactly the same fields as the real payload.
    """
    metadata: dict[str, Any] = {
        "cover_type": "video",
        "lsb_depth": lsb_depth,
        "sample_rate": sample_rate,
        "channels": channels,
        "sample_count": sample_count,
    }
    if note:
        metadata["note"] = note
    return metadata


def location_media_id(media_id: str) -> str:
    """Media ID used for the HMAC start location.

    The "video:" prefix keeps video positions separate from audio positions
    derived from the same secret, without changing the shared crypto code.
    """
    return f"video:{media_id}"


def check_duration(wav: WavData) -> None:
    """Raise VideoStegoError if the audio is longer than MAX_DURATION_SECONDS."""
    if wav.frame_rate <= 0:
        raise VideoStegoError("Audio has an invalid frame rate")

    duration = wav.frame_count / wav.frame_rate

    if duration > MAX_DURATION_SECONDS:
        raise VideoStegoError(
            f"Video is {duration:.2f}s long, longer than the "
            f"{MAX_DURATION_SECONDS}s maximum"
        )


def require_video_and_audio(streams: list[StreamInfo]) -> tuple[StreamInfo, StreamInfo]:
    """Encode side: the cover needs at least one video and one audio stream.

    Extra streams (e.g. a phone's metadata track) are fine, because remux only
    copies the first video and first audio into the stego file. Returns the
    first video and first audio stream, the same ones extract_audio and remux use.
    """
    video_streams = [stream for stream in streams if stream.kind == "v"]
    audio_streams = [stream for stream in streams if stream.kind == "a"]

    if not video_streams:
        raise VideoStegoError("This file has no video stream")
    if not audio_streams:
        raise VideoStegoError("This video has no audio track, so there is nowhere to hide the payload")

    return video_streams[0], audio_streams[0]


def require_exact_layout(streams: list[StreamInfo]) -> tuple[StreamInfo, StreamInfo]:
    """Require exactly one video stream and one audio stream.

    Our encoder always outputs exactly video + audio, so anything else (an
    added audio or subtitle track, a missing stream) means the file isn't what
    we produced. Returns (video_stream, audio_stream).
    """
    video_streams = [stream for stream in streams if stream.kind == "v"]
    audio_streams = [stream for stream in streams if stream.kind == "a"]

    if len(streams) != 2 or len(video_streams) != 1 or len(audio_streams) != 1:
        found = [stream.kind for stream in streams]
        raise VideoTamperedError(
            f"Video must contain exactly one video stream and one audio stream (found: {found})"
        )

    return video_streams[0], audio_streams[0]


def video_media_bytes(video_sha256: bytes, stable_audio: bytes) -> bytes:
    """Build the bytes whose SHA-256 goes into the signed payload.

    Binding BOTH streams means swapping the video frames is detected,
    not just audio edits.
    """
    if len(video_sha256) != 32:
        raise VideoStegoError("Video SHA-256 must be exactly 32 bytes")

    return HASH_DOMAIN + video_sha256 + stable_audio
