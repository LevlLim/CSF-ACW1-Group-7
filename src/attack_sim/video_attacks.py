"""Attack simulations for the video cover object.

Each attack mimics something a real attacker (or a real editing app) would do
to a protected video, saves the attacked copy, then runs the real video
verifier on it. A defended attack is any verdict other than Authentic.
"""

from __future__ import annotations

import math
from pathlib import Path
from tempfile import TemporaryDirectory

from audio_decoder import extract_envelope
from audio_stego.common import HEADER_BYTES, carrier_count_for_bytes, load_wav_pcm, save_wav_pcm
from audio_stego.locations import header_length_bytes, resolve_header_start_sample, resolve_payload_start_sample
from crypto_payload import generate_ed25519_keypair
from video_decoder import decode_video_file
from video_stego.common import MAX_DURATION_SECONDS, location_media_id
from video_stego.video_processing import (  # the same safe ffmpeg runner the encoder uses
    _run_ffmpeg,
    _safe_path,
    extract_audio,
    remux,
)

from .models import AttackSimulationResult

# Keeps re-encoding attacks quick; quality is irrelevant for an attack copy.
_FAST_H264 = ["-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p"]
# libx264 needs even frame dimensions.
_EVEN_SIZE = "scale=trunc(iw/2)*2:trunc(ih/2)*2"


def simulate_video_frame_edit(
    stego_path: str | Path, output_path: str | Path, *,
    lsb_depth: int, start_secret: bytes, media_id: str, public_key_pem: bytes,
) -> AttackSimulationResult:
    """Deepfake-style: change the picture but keep the original (payload-carrying) audio."""
    _run_ffmpeg([
        "-i", _safe_path(stego_path),
        "-vf", f"{_EVEN_SIZE},hflip,drawbox=x=iw/4:y=ih/4:w=iw/2:h=ih/2:color=black:t=fill",
        *_FAST_H264,
        "-c:a", "copy",
        "-f", "mp4", _safe_path(output_path),
    ])
    return _verify(
        "Frame edit (deepfake-style)", output_path, lsb_depth, start_secret, media_id, public_key_pem,
        "Mirrored the picture and blacked out its centre; the original stego audio was kept bit-for-bit.",
    )


def simulate_video_audio_edit(
    stego_path: str | Path, output_path: str | Path, *,
    lsb_depth: int, start_secret: bytes, media_id: str, public_key_pem: bytes,
) -> AttackSimulationResult:
    """Dubbing-style: replace 0.1 s of sound, away from the hidden payload so it still extracts."""
    with TemporaryDirectory() as temp_name:
        wav_path = Path(temp_name) / "audio.wav"
        extract_audio(stego_path, wav_path, max_seconds=MAX_DURATION_SECONDS + 1)
        wav = load_wav_pcm(wav_path)

        window = max(1, wav.frame_rate * wav.channels // 10)
        start = _free_window(wav, window, lsb_depth, start_secret, media_id)

        samples = list(wav.samples)
        for i in range(start, start + window):
            samples[i] = int(8000 * math.sin(i / 7))  # a different sound, like a dubbed word
        save_wav_pcm(wav_path, wav, tuple(samples))
        remux(stego_path, wav_path, output_path)

    seconds = start / (wav.frame_rate * wav.channels)
    return _verify(
        "Audio edit (dubbed words)", output_path, lsb_depth, start_secret, media_id, public_key_pem,
        f"Replaced 0.1 s of sound at {seconds:.2f} s; the hidden payload itself was left intact.",
    )


def simulate_video_extra_track(
    stego_path: str | Path, output_path: str | Path, *,
    lsb_depth: int, start_secret: bytes, media_id: str, public_key_pem: bytes,
) -> AttackSimulationResult:
    """Fake narration: add a second audio track next to the genuine one."""
    _run_ffmpeg([
        "-i", _safe_path(stego_path),
        "-f", "lavfi", "-t", "2", "-i", "sine=frequency=880",
        "-map", "0", "-map", "1:a",
        "-c", "copy", "-c:a:1", "aac",
        "-f", "mp4", _safe_path(output_path),
    ])
    return _verify(
        "Extra audio track (fake narration)", output_path, lsb_depth, start_secret, media_id, public_key_pem,
        "Added a second audio track; the original video and stego audio were copied unchanged.",
    )


def simulate_video_reexport(
    stego_path: str | Path, output_path: str | Path, *,
    lsb_depth: int, start_secret: bytes, media_id: str, public_key_pem: bytes,
) -> AttackSimulationResult:
    """Editing-app style: trim the last second and re-export (video and audio re-compressed)."""
    with TemporaryDirectory() as temp_name:
        wav_path = Path(temp_name) / "audio.wav"
        extract_audio(stego_path, wav_path, max_seconds=MAX_DURATION_SECONDS + 1)
        wav = load_wav_pcm(wav_path)
    duration = wav.frame_count / wav.frame_rate
    keep = max(duration - 1, duration / 2)

    _run_ffmpeg([
        "-i", _safe_path(stego_path),
        "-t", f"{keep:.3f}",
        "-vf", _EVEN_SIZE,
        *_FAST_H264,
        "-c:a", "aac",
        "-f", "mp4", _safe_path(output_path),
    ])
    return _verify(
        "Edit + re-export (trim 1 s)", output_path, lsb_depth, start_secret, media_id, public_key_pem,
        f"Trimmed to {keep:.1f} s and re-exported like an editing app (lossy AAC audio).",
    )


def simulate_video_wrong_key(
    stego_path: str | Path, *, lsb_depth: int, start_secret: bytes, media_id: str,
) -> AttackSimulationResult:
    """Impersonator: the file is checked against a public key that didn't sign it."""
    _, someone_elses_public_key = generate_ed25519_keypair()
    return _verify(
        "Wrong-key verification (impersonator)", stego_path, lsb_depth, start_secret, media_id,
        someone_elses_public_key, "Verified the genuine stego video with an unrelated public key.",
        output_path=None,
    )


def simulate_video_wrong_start_location(
    stego_path: str | Path, *, lsb_depth: int, start_secret: bytes, media_id: str, public_key_pem: bytes,
) -> AttackSimulationResult:
    """Attacker without the secret: guesses it, so derives the wrong start location."""
    return _verify(
        "Wrong start location (guessed secret)", stego_path, lsb_depth, start_secret + b"-guess",
        media_id, public_key_pem, "Derived the start location from a guessed secret.",
        output_path=None,
    )


def _verify(
    name: str, video: str | Path, lsb_depth: int, start_secret: bytes, media_id: str,
    public_key_pem: bytes, details: str, *, output_path: str | Path | None = "same",
) -> AttackSimulationResult:
    result = decode_video_file(
        video, lsb_depth=lsb_depth, start_secret=start_secret, media_id=media_id, public_key_pem=public_key_pem,
    )
    saved = Path(video) if output_path == "same" else (Path(output_path) if output_path else None)
    return AttackSimulationResult(attack_name=name, verdict=result.verdict, output_path=saved, details=details)


def _free_window(wav: object, window: int, lsb_depth: int, start_secret: bytes, media_id: str) -> int:
    """First run of `window` samples that doesn't overlap the hidden header or payload."""
    samples = wav.samples  # type: ignore[attr-defined]
    location_id = location_media_id(media_id)
    capacity = len(samples)

    header_start = resolve_header_start_sample(capacity, lsb_depth, start_secret, location_id)
    header_len = carrier_count_for_bytes(header_length_bytes(), lsb_depth)
    envelope = extract_envelope(wav, lsb_depth=lsb_depth, start_secret=start_secret, media_id=location_id)  # type: ignore[arg-type]
    framed_len = HEADER_BYTES + len(envelope)
    payload_start = resolve_payload_start_sample(capacity, lsb_depth, start_secret, location_id, framed_len)
    payload_len = carrier_count_for_bytes(framed_len, lsb_depth)
    protected = [(header_start, header_start + header_len), (payload_start, payload_start + payload_len)]

    for start in range(0, capacity - window + 1, window):
        if all(start + window <= lo or hi <= start for lo, hi in protected):
            return start
    raise ValueError("audio is too short to edit without touching the hidden payload")
