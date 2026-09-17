from crypto_payload import generate_ed25519_keypair

from audio_stego import encode_audio_file
from audio_stego.common import (
    load_wav_pcm,
    stable_audio_bytes,
)

import hashlib


private_key, public_key = generate_ed25519_keypair()

start_secret = b"group7-test-secret"

original_wav = load_wav_pcm(
    "samples/test_audio.wav"
)


for depth in range(1, 9):

    output_path = (
        f"samples/stego_audio_{depth}bit.wav"
    )

    print(
        f"\n========== {depth} LSB =========="
    )

    result = encode_audio_file(
        input_path="samples/test_audio.wav",
        output_path=output_path,
        media_id="AUDIO001",
        private_key_pem=private_key,
        start_secret=start_secret,
        lsb_depth=depth,
    )

    stego_wav = load_wav_pcm(
        output_path
    )

    # Stable representation
    original_stable = stable_audio_bytes(
        original_wav,
        depth
    )

    stego_stable = stable_audio_bytes(
        stego_wav,
        depth
    )

    original_hash = hashlib.sha256(
        original_stable
    ).hexdigest()

    stego_hash = hashlib.sha256(
        stego_stable
    ).hexdigest()

    print(
        "Start location:",
        result.start_location
    )

    print(
        "Payload bytes:",
        result.payload_bytes
    )

    print(
        "Carriers used:",
        result.carriers_used
    )

    print(
        "Stable hash match:",
        original_hash == stego_hash
    )