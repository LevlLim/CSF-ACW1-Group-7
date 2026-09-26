"""Video encoder: hide a signed payload in a video's audio track.

The video stream is copied untouched; the payload goes into the audio
using the team's existing audio LSB code; one signature covers BOTH streams.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization

from audio_stego.common import (
    carrier_count_for_bytes,
    frame_payload,
    load_wav_pcm,
    save_wav_pcm,
    stable_audio_bytes,
)
from audio_stego.encoder import embed_lsb
from audio_stego.locations import (
    HEADER_MAGIC,
    resolve_header_start_sample,
    resolve_payload_start_sample,
)
from crypto_payload import Verdict, build_payload, sign_payload

from .common import (
    MAX_DURATION_SECONDS,
    check_duration,
    location_media_id,
    require_video_and_audio,
    video_media_bytes,
    video_metadata,
)
from .models import VideoEncodeResult
from .video_processing import (
    VideoStegoError,
    extract_audio,
    probe_streams,
    remux,
)


def encode_video_file(
    input_path: str | Path,
    output_path: str | Path,
    media_id: str,
    private_key_pem: bytes,
    start_secret: bytes,
    lsb_depth: int,
    note: str = "",
) -> VideoEncodeResult:
    """Complete video encoding workflow — the function the GUI calls.

    Everything is built in a temporary folder, verified by decoding it
    (self-check), and only then moved to output_path — so the user never
    receives a broken or unverifiable file.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    with TemporaryDirectory() as temp_name:
        temp_dir = Path(temp_name)

        # 1. The cover needs at least one video and one audio stream.
        streams = probe_streams(input_path)
        video_stream, _ = require_video_and_audio(streams)

        # 2. Extract the video's audio so the existing audio steganography can use it.
        #    Extraction stops just past the limit, so a 2-hour movie is rejected
        #    without first writing a huge WAV and loading it all into memory.
        wav_path = temp_dir / "audio.wav"
        extract_audio(input_path, wav_path, max_seconds=MAX_DURATION_SECONDS + 1)

        wav = load_wav_pcm(wav_path)
        check_duration(wav)

        # 3. Hash the video and stable audio together so both streams are protected.
        stable_audio = stable_audio_bytes(wav, lsb_depth)
        media_bytes = video_media_bytes(video_stream.sha256, stable_audio)
        media_hash = hashlib.sha256(media_bytes).digest()

        # 4. Build and sign the payload with the video metadata and media hash.
        metadata = video_metadata(lsb_depth, wav.frame_rate, wav.channels, len(wav.samples), note)
        payload = build_payload(media_id, media_hash, metadata)
        envelope = sign_payload(payload, private_key_pem)

        # 5. Frame the signed envelope and check that the audio has enough capacity.
        framed = frame_payload(envelope)
        header = HEADER_MAGIC + len(framed).to_bytes(4, "big")

        needed = (
            carrier_count_for_bytes(len(header), lsb_depth)
            + carrier_count_for_bytes(len(framed), lsb_depth)
        )

        if needed > len(wav.samples):
            raise VideoStegoError(
                "Payload is too large for this video's audio at this LSB depth"
            )

        # 6. Find secret positions and hide the header and payload in the audio.
        location_id = location_media_id(media_id)
        capacity = len(wav.samples)

        try:
            header_start = resolve_header_start_sample(
                capacity,
                lsb_depth,
                start_secret,
                location_id,
            )

            payload_start = resolve_payload_start_sample(
                capacity,
                lsb_depth,
                start_secret,
                location_id,
                len(framed),
            )
        except ValueError as exc:
            raise VideoStegoError(
                "Could not find safe positions for the header and payload"
            ) from exc

        stego_samples = embed_lsb(
            wav.samples,
            header,
            header_start,
            lsb_depth,
        )

        stego_samples = embed_lsb(
            stego_samples,
            framed,
            payload_start,
            lsb_depth,
        )

        # 7. Save the modified audio and put it back into the original video.
        stego_wav = temp_dir / "stego.wav"
        save_wav_pcm(stego_wav, wav, stego_samples)

        temp_video = temp_dir / "stego.mp4"
        remux(input_path, stego_wav, temp_video)

        # 8. Self-check: decode our own output and require Authentic before
        #    handing it over. Proves the payload survived remuxing.
        _self_check(temp_video, private_key_pem, start_secret, media_id, lsb_depth)

        # 9. Move the finished video to the user's requested output path.
        #    shutil.move, not os.replace: the temp folder is on C:, and the
        #    user may save to another drive (USB stick, D:), which os.replace can't do.
        shutil.move(temp_video, output_path)

    # 10. Return the non-secret details for the GUI and the diagnostics visuals.
    return VideoEncodeResult(
        output_path=output_path,
        lsb_depth=lsb_depth,
        capacity_bytes=capacity * lsb_depth // 8,
        payload_bytes=len(framed),
        header_start_sample=header_start,
        payload_start_sample=payload_start,
        carriers_used=needed,
        sample_rate=wav.frame_rate,
        channels=wav.channels,
        video_hash_hex=video_stream.sha256.hex(),
    )


def _self_check(
    video: Path, private_key_pem: bytes, start_secret: bytes, media_id: str, lsb_depth: int
) -> None:
    """Decode a freshly encoded video exactly as Party B will, and raise unless Authentic."""
    # Imported here, not at the top of the file: video_decoder imports
    # video_stego, so a top-level import would be circular.
    from video_decoder import decode_video_file

    # The encoder only holds the private key; the matching public key is derived from it.
    # (sign_payload has already rejected an invalid or non-Ed25519 key by this point.)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    check = decode_video_file(
        video,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )
    if check.verdict != Verdict.AUTHENTIC:
        reason = next((line for line in check.explanation if line.startswith("Verification failed")), "")
        raise VideoStegoError(f"Self-check failed ({check.verdict}). {reason}")
