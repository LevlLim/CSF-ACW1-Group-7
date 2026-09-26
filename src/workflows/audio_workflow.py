"""Audio workflow: wires crypto_payload + audio steganography modules together.

No GUI toolkit here, so the GUI, a demo script, or tests can all call it the same way.
Mirrors image_workflow.py's encode/decode workflow shape.

Accepts WAV and FLAC: a FLAC is converted to WAV for the (unchanged) audio code,
and a stego output saved as .flac is converted back — see audio_formats.py.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from audio_decoder import AudioDecodeResult, decode_audio_file
from audio_stego import AudioEncodeResult, WavData, encode_audio_file
from audio_stego.common import AudioStegoError, audio_capacity_bytes, frame_payload, load_wav_pcm
from audio_stego.encoder import create_signed_audio_payload
from audio_stego_visuals import AudioStegoVisuals, build_visuals
from crypto_payload import SerializationFormatError, verdict_for_error

from .audio_formats import save_wav_as_flac, to_wav, wants_flac


class AudioCapacityStatus:
    """Whether a signed envelope fits in a cover WAV at a given LSB depth."""

    def __init__(self, fits: bool, needed_bytes: int, capacity_bytes: int) -> None:
        self.fits = fits
        self.needed_bytes = needed_bytes
        self.capacity_bytes = capacity_bytes


def read_audio(path: Path) -> WavData:
    """Load a WAV or FLAC file as PCM samples (for the GUI's cover info)."""
    with TemporaryDirectory() as temp_name:
        wav_path = to_wav(path, Path(temp_name) / "audio.wav")
        return load_wav_pcm(wav_path)


def check_audio_capacity(
    cover_path: Path,
    media_id: str,
    private_key_pem: bytes,
    lsb_depth: int,
    note: str = "",
    *,
    start_secret: bytes = b"",
    encrypt_payload: bool = False,
) -> AudioCapacityStatus:
    """Build the signed FR3/FR4 payload for the cover WAV and report whether
    the framed envelope fits at the selected LSB depth, without embedding.
    """
    wav = read_audio(cover_path)
    signed_envelope = create_signed_audio_payload(
        wav,
        media_id,
        private_key_pem,
        lsb_depth,
        note=note,
        encrypt_payload=encrypt_payload,
        start_secret=start_secret,
    )
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
    encrypt_payload: bool = False,
) -> AudioEncodeResult:
    """Embed into a WAV or FLAC cover; the output format follows stego_path's extension."""
    with TemporaryDirectory() as temp_name:
        cover_wav = to_wav(cover_path, Path(temp_name) / "cover.wav")

        # The audio code always writes WAV; for a .flac output, write a temporary
        # WAV first and compress it losslessly afterwards.
        target = Path(temp_name) / "stego.wav" if wants_flac(stego_path) else Path(stego_path)
        result = encode_audio_file(
            input_path=cover_wav,
            output_path=target,
            media_id=media_id,
            private_key_pem=private_key_pem,
            start_secret=start_secret,
            lsb_depth=lsb_depth,
            note=note,
            encrypt_payload=encrypt_payload,
        )
        if wants_flac(stego_path):
            save_wav_as_flac(target, stego_path)
            result = replace(result, output_path=Path(stego_path))
    return result


def decode_audio(
    stego_path: Path | str,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> AudioDecodeResult:
    """Extract and verify a signed payload from a stego WAV or FLAC."""
    try:
        with TemporaryDirectory() as temp_name:
            wav_path = to_wav(stego_path, Path(temp_name) / "stego.wav")
            return decode_audio_file(
                wav_path,
                lsb_depth=lsb_depth,
                start_secret=start_secret,
                media_id=media_id,
                public_key_pem=public_key_pem,
            )
    except AudioStegoError as exc:
        # Unsupported or unreadable file: same verdict the audio decoder gives for a bad WAV.
        error = SerializationFormatError(str(exc))
        return AudioDecodeResult(verdict=verdict_for_error(error), payload=None, error=error)


def build_audio_visuals(cover_path: Path, stego_path: Path, lsb_depth: int) -> AudioStegoVisuals:
    """The team's WAV diagnostics, for WAV or FLAC files."""
    with TemporaryDirectory() as temp_name:
        cover_wav = to_wav(cover_path, Path(temp_name) / "cover.wav")
        stego_wav = to_wav(stego_path, Path(temp_name) / "stego.wav")
        return build_visuals(cover_wav, stego_wav, lsb_depth)
