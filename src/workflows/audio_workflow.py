"""Audio workflow: wires crypto_payload + audio steganography modules together.

No GUI toolkit here, so the GUI, a demo script, or tests can all call it the same way.
Mirrors image_workflow.py's encode/decode workflow shape.
"""

from __future__ import annotations

from pathlib import Path

from audio_decoder import AudioDecodeResult, decode_audio_file
from audio_stego import AudioEncodeResult, encode_audio_file
from audio_stego.common import audio_capacity_bytes, frame_payload, load_wav_pcm
from audio_stego.encoder import create_signed_audio_payload


class AudioCapacityStatus:
    """Whether a signed envelope fits in a cover WAV at a given LSB depth."""

    def __init__(self, fits: bool, needed_bytes: int, capacity_bytes: int) -> None:
        self.fits = fits
        self.needed_bytes = needed_bytes
        self.capacity_bytes = capacity_bytes


def check_audio_capacity(
    cover_path: Path, media_id: str, private_key_pem: bytes, lsb_depth: int, note: str = ""
) -> AudioCapacityStatus:
    """Build the signed FR3/FR4 payload for the cover WAV and report whether
    the framed envelope fits at the selected LSB depth, without embedding.
    """
    wav = load_wav_pcm(cover_path)
    signed_envelope = create_signed_audio_payload(wav, media_id, private_key_pem, lsb_depth, note=note)
    needed_bytes = len(frame_payload(signed_envelope))
    capacity_bytes = audio_capacity_bytes(len(wav.samples), lsb_depth)
    return AudioCapacityStatus(fits=needed_bytes <= capacity_bytes, needed_bytes=needed_bytes, capacity_bytes=capacity_bytes)


def encode_audio(
    cover_path: Path,
    stego_path: Path | str,
    media_id: str,
    private_key_pem: bytes,
    start_secret: bytes,
    lsb_depth: int,
    note: str = "",
) -> AudioEncodeResult:
    return encode_audio_file(
        input_path=cover_path,
        output_path=stego_path,
        media_id=media_id,
        private_key_pem=private_key_pem,
        start_secret=start_secret,
        lsb_depth=lsb_depth,
        note=note,
    )


def decode_audio(
    stego_path: Path | str,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> AudioDecodeResult:
    """Extract and verify a signed payload from a stego WAV."""
    return decode_audio_file(
        stego_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )
