from __future__ import annotations

import hashlib
from pathlib import Path

from crypto_payload import (
    build_payload,
    derive_start_location,
    sign_payload,
)

from .common import (
    AudioStegoError,
    carrier_count_for_bytes,
    frame_payload,
    load_wav_pcm,
    save_wav_pcm,
    stable_audio_bytes,
    bytes_to_bits,
)

from .models import AudioEncodeResult

def embed_lsb(
    samples: tuple[int, ...],
    payload: bytes,
    start_location: int,
    lsb_depth: int,
) -> tuple[int, ...]:
    """Embed payload bytes into PCM samples using LSB replacement."""

    if not 1 <= lsb_depth <= 8:
        raise ValueError(
            "lsb_depth must be between 1 and 8"
        )

    if start_location < 0:
        raise AudioStegoError(
            "Start location cannot be negative"
        )

    payload_bits = bytes_to_bits(payload)

    carriers_needed = (
        len(payload_bits) + lsb_depth - 1
    ) // lsb_depth

    if (
        start_location + carriers_needed
        > len(samples)
    ):
        raise AudioStegoError(
            "Payload does not fit in audio file"
        )

    output = list(samples)

    clear_mask = ~(
        (1 << lsb_depth) - 1
    )

    bit_index = 0

    for sample_index in range(
        start_location,
        start_location + carriers_needed
    ):

        value = 0

        for _ in range(lsb_depth):

            value <<= 1

            if bit_index < len(payload_bits):
                value |= payload_bits[bit_index]
                bit_index += 1

        output[sample_index] = (
            output[sample_index]
            & clear_mask
        ) | value

    return tuple(output)

def create_signed_audio_payload(

    wav,
    media_id: str,
    private_key_pem: bytes,
    lsb_depth: int,
    note: str = "",
) -> bytes:
    """
    Create and digitally sign the verification payload
    using Person 5's crypto_payload library.
    """

    # 1. Create stable audio representation
    stable_bytes = stable_audio_bytes(
        wav,
        lsb_depth
    )

    # 2. SHA-256 produces 32 raw bytes
    media_hash = hashlib.sha256(
        stable_bytes
    ).digest()

    # 3. creates FR3 payload
    metadata = {
        "cover_type": "audio",
        "lsb_depth": lsb_depth,
    }
    if note:
        metadata["note"] = note

    payload = build_payload(
        media_id=media_id,
        media_hash=media_hash,
        metadata=metadata,
    )

    signed_envelope = sign_payload(
        payload,
        private_key_pem,
    )

    return signed_envelope

def encode_audio_file(
    input_path: str | Path,
    output_path: str | Path,
    media_id: str,
    private_key_pem: bytes,
    start_secret: bytes,
    lsb_depth: int,
    note: str = "",
) -> AudioEncodeResult:
    """
    Complete audio encoding workflow.

    This is the main function that the GUI should call.
    """
    # 1. Load original WAV

    wav = load_wav_pcm(
        input_path
    )

    # 2. Create signed verification data

    signed_envelope = (
        create_signed_audio_payload(
            wav=wav,
            media_id=media_id,
            private_key_pem=private_key_pem,
            lsb_depth=lsb_depth,
            note=note,
        )
    )
    # 3. Add audio framing

    framed_payload = frame_payload(
        signed_envelope
    )

    # 4. Determine how many samples are required

    carriers_needed = (
        carrier_count_for_bytes(
            len(framed_payload),
            lsb_depth,
        )
    )

    capacity = len(
        wav.samples
    )
    # 5. Capacity check
    if carriers_needed > capacity:
        raise AudioStegoError(
            "Payload is too large for "
            "the selected audio file"
        )

    # 6. Person 5 derives secret start location

    start_location = (
        derive_start_location(
            secret=start_secret,
            media_id=media_id,
            cover_type="audio",
            capacity=capacity,
            payload_length=carriers_needed,
        )
    )

    # LSB embedding
    stego_samples = embed_lsb(
        samples=wav.samples,
        payload=framed_payload,
        start_location=start_location,
        lsb_depth=lsb_depth,
    )
    # 8. Save new WAV
    save_wav_pcm(
        output_path=output_path,
        wav=wav,
        samples=stego_samples,
    )
    # 9. Return useful information to GUI

    return AudioEncodeResult(
        output_path=Path(output_path),
        start_location=start_location,
        lsb_depth=lsb_depth,
        payload_bytes=len(framed_payload),
        carriers_used=carriers_needed,
        capacity=capacity,
    )