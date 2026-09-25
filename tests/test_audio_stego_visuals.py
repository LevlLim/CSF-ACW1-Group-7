"""Tests for WAV LSB visual diagnostics."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from audio_stego.common import AudioStegoError, save_wav_pcm
from audio_stego.models import WavData
from audio_stego_visuals import build_visuals


class AudioStegoVisualTests(unittest.TestCase):
    def test_visuals_report_changed_samples_and_bits(self) -> None:
        wav = WavData(samples=(0, 4, -8, 12), channels=1, sample_width=2, frame_rate=44100, frame_count=4)
        stego_samples = (3, 4, -5, 13)
        with tempfile.TemporaryDirectory() as tmp:
            cover_path = Path(tmp) / "cover.wav"
            stego_path = Path(tmp) / "stego.wav"
            save_wav_pcm(cover_path, wav, wav.samples)
            save_wav_pcm(stego_path, wav, stego_samples)

            visuals = build_visuals(cover_path, stego_path, lsb_depth=2)

        self.assertEqual(visuals.changed_samples, 3)
        self.assertEqual(visuals.changed_lsb_bits, 5)
        self.assertEqual(visuals.lsb_change_map.width, 4)
        self.assertNotEqual(visuals.density_timeline.getpixel((0, 159)), (11, 18, 32))

    def test_rejects_mismatched_pcm_properties(self) -> None:
        cover = WavData(samples=(0, 1), channels=1, sample_width=2, frame_rate=44100, frame_count=2)
        stego = WavData(samples=(0, 1, 2), channels=1, sample_width=2, frame_rate=44100, frame_count=3)
        with tempfile.TemporaryDirectory() as tmp:
            cover_path = Path(tmp) / "cover.wav"
            stego_path = Path(tmp) / "stego.wav"
            save_wav_pcm(cover_path, cover, cover.samples)
            save_wav_pcm(stego_path, stego, stego.samples)

            with self.assertRaises(AudioStegoError):
                build_visuals(cover_path, stego_path, lsb_depth=1)


if __name__ == "__main__":
    unittest.main()
