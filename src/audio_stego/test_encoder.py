from crypto_payload import (
    generate_ed25519_keypair,
)

from audio_stego import (
    encode_audio_file,
)


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
    input_path="samples/test_audio.wav",
    output_path="samples/stego_audio.wav",
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

from audio_stego.common import load_wav_pcm


stego_wav = load_wav_pcm(
    "samples/stego_audio.wav"
)

print("\nStego WAV information")
print("Channels:", stego_wav.channels)
print("Sample width:", stego_wav.sample_width)
print("Frame rate:", stego_wav.frame_rate)
print("Frame count:", stego_wav.frame_count)
print("Number of samples:", len(stego_wav.samples))

original_wav = load_wav_pcm(
    "samples/test_audio.wav"
)

stego_wav = load_wav_pcm(
    "samples/stego_audio.wav"
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


before_same = (
    original_wav.samples[:start]
    == stego_wav.samples[:start]
)

after_same = (
    original_wav.samples[end:]
    == stego_wav.samples[end:]
)


print("\nOutside embedding region check")
print(
    "Before payload unchanged:",
    before_same
)

print(
    "After payload unchanged:",
    after_same
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