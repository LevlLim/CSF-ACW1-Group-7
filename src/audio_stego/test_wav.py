from audio_stego.common import load_wav_pcm
from audio_stego.common import (
    load_wav_pcm,
    bytes_to_bits,
    audio_capacity_bytes,
    carrier_count_for_bytes,
)

wav = load_wav_pcm("test_audio.wav")

# print("Channels:", wav.channels)
# print("Sample width:", wav.sample_width)
# print("Frame rate:", wav.frame_rate)
# print("Frame count:", wav.frame_count)
# print("Number of samples:", len(wav.samples))

# print("\nFirst 10 samples:")
# print(wav.samples[:10])

print("Number of samples:", len(wav.samples))

for depth in range(1, 9):

    capacity = audio_capacity_bytes(
        len(wav.samples),
        depth
    )

    print(
        f"{depth} LSB(s): "
        f"{capacity} bytes capacity"
    )