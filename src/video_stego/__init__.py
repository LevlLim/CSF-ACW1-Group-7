"""Video steganography: payload hidden in the audio track, video stream copied untouched."""

from .encoder import encode_video_file
from .models import VideoEncodeResult
from .video_processing import VideoStegoError

__all__ = [
    "encode_video_file",
    "VideoEncodeResult",
    "VideoStegoError",
]
