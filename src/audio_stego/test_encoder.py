from pathlib import Path
from tempfile import TemporaryDirectory

from crypto_payload import (
    generate_ed25519_keypair,
)

from audio_stego import (
    encode_audio_file,
)


_repo_root = Path(__file__).resolve().parents[2]
_temp_dir = TemporaryDirectory()
input_path = _repo_root / "Sample Files" / "wav_orig.wav"
output_path = Path(_temp_dir.name) / "stego_audio.wav"


# --------------------------------
# TEMPORARY TEST KEYS
# --------------------------------

private_key, public_key = (
    generate_ed25519_keypair()
)


# --------------------------------
# TEST START-LOCATION SECRET
# --------------------------------

start_secret = (
    b"group7-test-secret"
)


# --------------------------------
# RUN AUDIO ENCODER
# --------------------------------

result = encode_audio_file(
    input_path=input_path,
    output_path=output_path,
    media_id="AUDIO001",
    private_key_pem=private_key,
    start_secret=start_secret,
    lsb_depth=1,
)


print("\nEncoding completed")

print(
    "Output:",
    result.output_path
)

print(
    "Start location:",
    result.start_location
)

print(
    "LSB depth:",
    result.lsb_depth
)

print(
    "Payload bytes:",
    result.payload_bytes
)

print(
    "Carrier samples used:",
    result.carriers_used
)

print(
    "Audio capacity:",
    result.capacity
)

from audio_stego.common import carrier_count_for_bytes, load_wav_pcm
from audio_stego.locations import header_length_bytes, resolve_header_start_sample


stego_wav = load_wav_pcm(
    output_path
)

print("\nStego WAV information")
print("Channels:", stego_wav.channels)
print("Sample width:", stego_wav.sample_width)
print("Frame rate:", stego_wav.frame_rate)
print("Frame count:", stego_wav.frame_count)
print("Number of samples:", len(stego_wav.samples))

original_wav = load_wav_pcm(
    input_path
)

stego_wav = load_wav_pcm(
    output_path
)


changed_indices = []

for i, (original, stego) in enumerate(
    zip(original_wav.samples, stego_wav.samples)
):
    if original != stego:
        changed_indices.append(i)


print("\nLSB modification check")
print("Changed samples:", len(changed_indices))

if changed_indices:
    print(
        "First changed sample:",
        changed_indices[0]
    )

    print(
        "Last changed sample:",
        changed_indices[-1]
    )

start = result.start_location
end = start + result.carriers_used
header_start = resolve_header_start_sample(
    result.capacity, result.lsb_depth, start_secret, "AUDIO001"
)
header_end = header_start + carrier_count_for_bytes(
    header_length_bytes(), result.lsb_depth
)

outside_same = all(
    original == stego
    for index, (original, stego) in enumerate(
        zip(original_wav.samples, stego_wav.samples)
    )
    if not (header_start <= index < header_end or start <= index < end)
)


print("\nOutside embedding region check")
print(
    "Outside locator and payload unchanged:",
    outside_same
)

import hashlib

from audio_stego.common import (
    stable_audio_bytes,
)


original_stable = stable_audio_bytes(
    original_wav,
    lsb_depth=1
)

stego_stable = stable_audio_bytes(
    stego_wav,
    lsb_depth=1
)


original_hash = hashlib.sha256(
    original_stable
).hexdigest()

stego_hash = hashlib.sha256(
    stego_stable
).hexdigest()


print("\nStable hash check")

print(
    "Original:",
    original_hash
)

print(
    "Stego:   ",
    stego_hash
)

print(
    "Hashes match:",
    original_hash == stego_hash
)

_temp_dir.cleanup()
