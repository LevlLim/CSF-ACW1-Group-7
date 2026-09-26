"""Video extraction and verification, matching video_stego/encoder.py exactly.

Returns a verdict AND a step-by-step explanation (spec section 7, steps 7 and 10:
the verifier must explain how the start location was recovered).

Fail closed: every error path ends in a non-Authentic verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from audio_decoder import extract_envelope
from audio_stego.common import HEADER_BYTES, AudioStegoError, load_wav_pcm, stable_audio_bytes
from audio_stego.locations import resolve_header_start_sample, resolve_payload_start_sample
from crypto_payload import (
    CryptoPayloadError,
    Verdict,
    VerificationPayload,
    media_hash_matches,
    parse_and_verify,
    verdict_for_error,
)

from video_stego.common import (
    MAX_DURATION_SECONDS,
    VideoTamperedError,
    check_duration,
    location_media_id,
    require_exact_layout,
    video_media_bytes,
)
from video_stego.video_processing import VideoStegoError, extract_audio, probe_streams


@dataclass(frozen=True, slots=True)
class VideoDecodeResult:
    """What the GUI needs to display after video decoding (FR10).

    ``payload`` is only set when the verdict is Authentic.
    """

    verdict: Verdict
    payload: VerificationPayload | None
    error: Exception | None
    explanation: tuple[str, ...]


def decode_video_file(
    stego_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> VideoDecodeResult:
    """Extract, verify, and produce a verdict + explanation for a stego video.

    ``lsb_depth``, ``start_secret`` and ``media_id`` must be the values used at
    encode time; they are agreed out of band, never read from the file.
    """
    explanation: list[str] = []

    try:
        payload = _decode_and_verify(
            Path(stego_path),
            lsb_depth=lsb_depth,
            start_secret=start_secret,
            media_id=media_id,
            public_key_pem=public_key_pem,
            explanation=explanation,
        )
    except VideoTamperedError as exc:
        return _failed_result(Verdict.TAMPERED, exc, explanation)
    except CryptoPayloadError as exc:
        # Missing/corrupted payload, invalid signature, bad key, etc.
        return _failed_result(verdict_for_error(exc), exc, explanation)
    except (VideoStegoError, AudioStegoError, ValueError, OSError) as exc:
        # The file couldn't be read as a video we can check at all.
        return _failed_result(Verdict.CANNOT_VERIFY, exc, explanation)

    explanation.append("Final verdict: Authentic.")
    return VideoDecodeResult(Verdict.AUTHENTIC, payload, None, tuple(explanation))


def _decode_and_verify(
    stego_path: Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
    explanation: list[str],
) -> VerificationPayload:
    """Run every check in order; raise on the first failure.

    Each passed step appends a line to ``explanation``, so on failure the
    user can see exactly how far verification got.
    """
    with TemporaryDirectory() as temp_name:
        temp_dir = Path(temp_name)

        # 1. The stego video must be exactly one video + one audio stream,
        #    because that is all our encoder ever outputs.
        video_stream, _ = require_exact_layout(probe_streams(stego_path))
        explanation.append("Layout check passed: exactly one video stream and one audio stream.")

        # 2. Extract the stego audio (capped, so a huge file can't exhaust memory).
        wav_path = temp_dir / "audio.wav"
        extract_audio(stego_path, wav_path, max_seconds=MAX_DURATION_SECONDS + 1)
        wav = load_wav_pcm(wav_path)
        check_duration(wav)
        explanation.append(
            f"Audio extracted: {wav.frame_rate} Hz, {wav.channels} channel(s), "
            f"{len(wav.samples)} samples."
        )

    # 3. Recover the signed envelope from the same HMAC-derived positions as the encoder.
    location_id = location_media_id(media_id)
    capacity = len(wav.samples)
    header_start = resolve_header_start_sample(capacity, lsb_depth, start_secret, location_id)
    explanation.append(
        f"Header position derived with HMAC(secret, '{location_id}'): sample {header_start}."
    )

    envelope = extract_envelope(
        wav, lsb_depth=lsb_depth, start_secret=start_secret, media_id=location_id
    )
    framed_length = HEADER_BYTES + len(envelope)  # "CSF7" magic + 4-byte length + envelope
    payload_start = resolve_payload_start_sample(
        capacity, lsb_depth, start_secret, location_id, framed_length
    )
    explanation.append(
        f"Header found; payload ({framed_length} bytes) read from sample {payload_start}."
    )

    # 4. Signature: proves the payload was issued by the holder of the private key.
    payload = parse_and_verify(envelope, public_key_pem)
    explanation.append("Signature verified with the supplied public key.")

    # 5. The signed metadata must describe THIS file. Catches edits the hash
    #    can't see, e.g. a container-level sample-rate change (speed-up).
    expected = {
        "cover_type": "video",
        "lsb_depth": lsb_depth,
        "sample_rate": wav.frame_rate,
        "channels": wav.channels,
        "sample_count": len(wav.samples),
    }
    for key, actual in expected.items():
        signed = payload.metadata.get(key)
        if signed != actual:
            raise VideoTamperedError(f"Signed {key} is {signed!r}, but the file has {actual!r}")
    explanation.append("Signed metadata matches the file (cover type, LSB depth, sample rate, channels, length).")

    # 6. Hash: recompute from BOTH streams, so swapped frames or edited audio are caught.
    media_bytes = video_media_bytes(video_stream.sha256, stable_audio_bytes(wav, lsb_depth))
    if not media_hash_matches(media_bytes, payload.media_hash):
        raise VideoTamperedError("Video/audio hash does not match the signed hash")
    explanation.append("Hash check passed: video stream and audio match the signed hash.")

    return payload


def _failed_result(verdict: Verdict, error: Exception, explanation: list[str]) -> VideoDecodeResult:
    """Build a non-Authentic result. Never returns the payload: it isn't trusted."""
    explanation.append(f"Verification failed: {error}")
    if verdict == Verdict.PAYLOAD_MISSING:
        explanation.append(
            "No valid payload at the position derived from this secret and media ID: "
            "either the secret/media ID is wrong, or the file has no payload."
        )
    explanation.append(f"Final verdict: {verdict}.")
    return VideoDecodeResult(verdict, None, error, tuple(explanation))
