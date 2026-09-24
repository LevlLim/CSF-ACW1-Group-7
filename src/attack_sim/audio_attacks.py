from __future__ import annotations

import base64
import json
from pathlib import Path

from audio_decoder import decode_audio_file

from audio_stego.common import (
    LENGTH_BYTES,
    MAGIC as FRAME_MAGIC,
    AudioStegoError,
    carrier_count_for_bytes,
    frame_payload,
    load_wav_pcm,
    save_wav_pcm,
)

from audio_stego.encoder import embed_lsb

from audio_stego.locations import (
    HEADER_MAGIC,
    header_length_bytes,
    resolve_header_start_sample,
    resolve_payload_start_sample,
)

from crypto_payload import generate_ed25519_keypair
from crypto_payload.core import _canonical_json_bytes

from .models import AttackSimulationResult

#Helper functions 
# Removes the audio framing header and returns the actual embedded payload
def _remove_frame(
    framed: bytes,
) -> bytes:

    if (
        framed[:len(FRAME_MAGIC)]
        != FRAME_MAGIC
    ):
        raise AudioStegoError(
            "Framed payload magic missing"
        )

    declared_length = int.from_bytes(
        framed[
            len(FRAME_MAGIC):
            len(FRAME_MAGIC) + LENGTH_BYTES
        ],
        "big",
    )

    envelope = framed[
        len(FRAME_MAGIC)
        + LENGTH_BYTES:
    ]

    if len(envelope) != declared_length:
        raise AudioStegoError(
            "Payload length mismatch"
        )

    return envelope

#Flips one selected bit in a PCM sample to simulate tampering
def _flip_sample_bit(
    sample: int,
    bit_position: int,
    bits_per_sample: int,
) -> int:

    mask = (
        (1 << bits_per_sample) - 1
    )

    unsigned = sample & mask

    # Flip chosen bit
    unsigned ^= (
        1 << bit_position
    )

    # 8-bit WAV is unsigned
    if bits_per_sample == 8:
        return unsigned

    # Convert back to signed PCM
    sign_bit = (
        1 << (bits_per_sample - 1)
    )

    if unsigned & sign_bit:
        return (
            unsigned
            - (1 << bits_per_sample)
        )

    return unsigned

#Converts JSON data into a consistent byte format before re-embedding it
def _canonical_json_bytes(
    value: object,
) -> bytes:

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

#Finds where the hidden header and payload are located in the audio
def _read_layout(
    samples: tuple[int, ...],
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
) -> dict[str, int]:

    capacity = len(samples)

    header_start = (
        resolve_header_start_sample(
            capacity,
            lsb_depth,
            start_secret,
            media_id,
        )
    )

    header_bytes = _extract_bytes(
        samples,
        header_start,
        header_length_bytes() * 8,
        lsb_depth,
    )

    if (
        header_bytes[:len(HEADER_MAGIC)]
        != HEADER_MAGIC
    ):
        raise AudioStegoError(
            "Could not find locator header"
        )

    framed_length = int.from_bytes(
        header_bytes[len(HEADER_MAGIC):],
        "big",
    )

    if framed_length <= 0:
        raise AudioStegoError(
            "Invalid framed payload length"
        )

    payload_start = (
        resolve_payload_start_sample(
            capacity,
            lsb_depth,
            start_secret,
            media_id,
            framed_length,
        )
    )

    return {
        "header_start": header_start,

        "header_carriers":
            carrier_count_for_bytes(
                header_length_bytes(),
                lsb_depth,
            ),

        "payload_start": payload_start,

        "payload_carriers":
            carrier_count_for_bytes(
                framed_length,
                lsb_depth,
            ),

        "framed_length": framed_length,
    }

#Finds a PCM sample that is not being used to store hidden data
def _find_unprotected_sample(
    capacity: int,
    layout: dict[str, int],
) -> int:

    blocked_regions = (
        (
            layout["header_start"],
            layout["header_start"]
            + layout["header_carriers"],
        ),
        (
            layout["payload_start"],
            layout["payload_start"]
            + layout["payload_carriers"],
        ),
    )

    for sample_index in range(capacity):

        inside_hidden_region = any(
            start <= sample_index < end
            for start, end in blocked_regions
        )

        if not inside_hidden_region:
            return sample_index

    raise AudioStegoError(
        "No free PCM sample could be found"
    )

#Reads hidden LSB bits from audio samples and converts them back into bytes
def _extract_bytes(
    samples: tuple[int, ...],
    start_location: int,
    num_bits: int,
    lsb_depth: int,
) -> bytes:

    bits = []

    sample_index = start_location

    mask = (
        (1 << lsb_depth) - 1
    )

    while len(bits) < num_bits:

        if sample_index >= len(samples):
            raise AudioStegoError(
                "Hidden data exceeds audio size"
            )

        remaining = (
            num_bits - len(bits)
        )

        take = min(
            lsb_depth,
            remaining,
        )

        value = (
            samples[sample_index]
            & mask
        )

        if take < lsb_depth:
            value >>= (
                lsb_depth - take
            )

        for shift in range(
            take - 1,
            -1,
            -1,
        ):
            bits.append(
                (value >> shift) & 1
            )

        sample_index += 1

    output = bytearray()

    for i in range(
        0,
        len(bits),
        8,
    ):

        byte = 0

        for bit in bits[i:i + 8]:
            byte = (
                byte << 1
            ) | bit

        output.append(byte)

    return bytes(output)


#Attack 1: audio tampering 
def simulate_audio_tampering(
    stego_path: str | Path,
    output_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> AttackSimulationResult:
    """
    Modify one real PCM audio bit while keeping
    the hidden payload untouched.
    """

    wav = load_wav_pcm(stego_path)

    layout = _read_layout(
        wav.samples,
        lsb_depth,
        start_secret,
        media_id,
    )

    # First bit ABOVE the LSB embedding region
    bit_to_flip = lsb_depth

    bits_per_sample = wav.sample_width * 8

    if bit_to_flip >= bits_per_sample:
        raise AudioStegoError(
            "No non-LSB audio bit is available to flip"
        )

    sample_index = _find_unprotected_sample(
        len(wav.samples),
        layout,
    )

    samples = list(wav.samples)

    samples[sample_index] = _flip_sample_bit(
        samples[sample_index],
        bit_to_flip,
        bits_per_sample,
    )

    save_wav_pcm(
        output_path,
        wav,
        tuple(samples),
    )

    verification = decode_audio_file(
        output_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )

    return AttackSimulationResult(
        attack_name="Audio tampering",
        verdict=verification.verdict,
        output_path=Path(output_path),
        details=(
            f"Flipped audio bit {bit_to_flip} "
            f"at PCM sample {sample_index}."
        ),
    )

#Attack 2: Wrong key veri 
def simulate_wrong_key_verification(
    stego_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
) -> AttackSimulationResult:
    """
    Verify a valid stego WAV using an unrelated
    Ed25519 public key.
    """

    # Generate another completely unrelated key pair
    _, wrong_public_key = generate_ed25519_keypair()

    verification = decode_audio_file(
        stego_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=wrong_public_key,
    )

    return AttackSimulationResult(
        attack_name="Wrong-key verification",
        verdict=verification.verdict,
        output_path=None,
        details=(
            "Verified the valid stego WAV using "
            "an unrelated public key."
        ),
    )

#Attack3 payload corruption
def simulate_payload_corruption(
    stego_path: str | Path,
    output_path: str | Path,
    *,
    lsb_depth: int,
    start_secret: bytes,
    media_id: str,
    public_key_pem: bytes,
) -> AttackSimulationResult:

    wav = load_wav_pcm(stego_path)

    layout = _read_layout(
        wav.samples,
        lsb_depth,
        start_secret,
        media_id,
    )

    # Extract complete framed payload
    framed = _extract_bytes(
        wav.samples,
        layout["payload_start"],
        layout["framed_length"] * 8,
        lsb_depth,
    )

    envelope_bytes = _remove_frame(
        framed
    )

    try:
        # Outer signed envelope
        envelope = json.loads(
            envelope_bytes.decode("utf-8")
        )

        # Decode the embedded payload
        payload_bytes = base64.urlsafe_b64decode(
            envelope["payload"]
        )

        payload = json.loads(
            payload_bytes.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:

        raise AudioStegoError(
            "Could not parse embedded signed payload"
        ) from exc

    old_media_id = payload.get(
        "media_id"
    )

    if (
        not isinstance(old_media_id, str)
        or not old_media_id
    ):
        raise AudioStegoError(
            "Payload contains no valid media_id"
        )

    # Change exactly one character
    replacement = (
        "X"
        if old_media_id[0] != "X"
        else "Y"
    )

    payload["media_id"] = (
        replacement
        + old_media_id[1:]
    )

    # Convert modified payload back to the same canonical JSON format 
    modified_payload_bytes = (
        _canonical_json_bytes(payload)
    )

    if (
        len(modified_payload_bytes)
        != len(payload_bytes)
    ):
        raise AudioStegoError(
            "Payload corruption changed payload length"
        )

    # Replace ONLY the payload, not new signature 
    envelope["payload"] = (
        base64.urlsafe_b64encode(
            modified_payload_bytes
        ).decode("ascii")
    )

    modified_envelope_bytes = (
        _canonical_json_bytes(envelope)
    )

    # Frame it again
    modified_framed = frame_payload(
        modified_envelope_bytes
    )

    # Replace the existing hidden payload at the same location
    modified_samples = embed_lsb(
        wav.samples,
        modified_framed,
        layout["payload_start"],
        lsb_depth,
    )

    save_wav_pcm(
        output_path,
        wav,
        modified_samples,
    )

    verification = decode_audio_file(
        output_path,
        lsb_depth=lsb_depth,
        start_secret=start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )

    return AttackSimulationResult(
        attack_name="Payload corruption",
        verdict=verification.verdict,
        output_path=Path(output_path),
        details=(
            f"Changed embedded media_id from "
            f"{old_media_id!r} to "
            f"{payload['media_id']!r} "
            f"without re-signing."
        ),
    )

#Attack 4 wrong start location

def simulate_wrong_start_location(
    stego_path: str | Path,
    *,
    lsb_depth: int,
    media_id: str,
    public_key_pem: bytes,
    wrong_start_secret: bytes = (
        b"attack-simulation-wrong-secret"
    ),
) -> AttackSimulationResult:
    """
    Attempt extraction using the wrong
    start-location secret.
    """

    verification = decode_audio_file(
        stego_path,
        lsb_depth=lsb_depth,
        start_secret=wrong_start_secret,
        media_id=media_id,
        public_key_pem=public_key_pem,
    )

    return AttackSimulationResult(
        attack_name=(
            "Wrong start-location extraction"
        ),
        verdict=verification.verdict,
        output_path=None,
        details=(
            "Attempted extraction using an "
            "incorrect start-location secret."
        ),
    )
