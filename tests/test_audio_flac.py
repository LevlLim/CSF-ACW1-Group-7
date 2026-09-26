"""Tests for the Audio tab's FLAC support (workflows/audio_formats.py + audio_workflow.py).

FLAC is lossless, so the existing audio LSB code must give exactly the same
verdicts for FLAC as for WAV. Lossy formats must still be rejected.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from audio_stego.common import AudioStegoError, load_wav_pcm, save_wav_pcm
from crypto_payload import Verdict, generate_ed25519_keypair
from video_stego.video_processing import FFMPEG, extract_audio, wav_to_flac
from workflows import audio_workflow
from workflows.audio_formats import is_flac

MEDIA_ID = "AUDIO-FLAC-TEST"
SECRET = b"test-secret"
LSB_DEPTH = 2


def _make_audio(path: Path, *codec_args: str) -> Path:
    """A 2-second tone, encoded with the given ffmpeg codec arguments."""
    command = [FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
               "-f", "lavfi", "-i", "sine=frequency=440:duration=2", *codec_args, str(path)]
    subprocess.run(command, check=True, capture_output=True)
    return path


class AudioFlacTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp_dir.cleanup)
        cls.folder = Path(temp_dir.name)

        cls.private_key_pem, cls.public_key_pem = generate_ed25519_keypair()
        cls.flac_cover = _make_audio(cls.folder / "cover.flac", "-c:a", "flac")
        cls.wav_cover = _make_audio(cls.folder / "cover.wav", "-c:a", "pcm_s16le")

    def _encode(self, cover: Path, output_name: str) -> Path:
        return audio_workflow.encode_audio(
            cover, self.folder / output_name, MEDIA_ID, self.private_key_pem, SECRET, LSB_DEPTH, note="hi"
        ).output_path

    def _verdict(self, stego: Path) -> Verdict:
        return audio_workflow.decode_audio(stego, LSB_DEPTH, SECRET, MEDIA_ID, self.public_key_pem).verdict

    def test_flac_to_flac(self) -> None:
        stego = self._encode(self.flac_cover, "stego.flac")

        self.assertTrue(is_flac(stego), "a .flac output must really be a FLAC file")
        self.assertEqual(self._verdict(stego), Verdict.AUTHENTIC)

    def test_wav_to_flac(self) -> None:
        self.assertEqual(self._verdict(self._encode(self.wav_cover, "from_wav.flac")), Verdict.AUTHENTIC)

    def test_flac_to_wav(self) -> None:
        stego = self._encode(self.flac_cover, "from_flac.wav")

        self.assertFalse(is_flac(stego), "a .wav output must really be a WAV file")
        self.assertEqual(self._verdict(stego), Verdict.AUTHENTIC)

    def test_24_bit_flac(self) -> None:
        """The audio code is 16-bit; a 24-bit FLAC cover is converted, not rejected."""
        cover = _make_audio(self.folder / "cover24.flac", "-c:a", "flac", "-sample_fmt", "s32", "-bits_per_raw_sample", "24")

        self.assertEqual(self._verdict(self._encode(cover, "stego24.flac")), Verdict.AUTHENTIC)

    def test_tampered_flac(self) -> None:
        stego = self._encode(self.flac_cover, "to_tamper.flac")
        wav_path = self.folder / "tamper.wav"
        extract_audio(stego, wav_path)
        wav = load_wav_pcm(wav_path)
        samples = list(wav.samples)
        samples[0] ^= 1 << 12  # a high bit: the hidden payload still extracts, the hash no longer matches
        save_wav_pcm(wav_path, wav, tuple(samples))
        tampered = self.folder / "tampered.flac"
        wav_to_flac(wav_path, tampered)

        self.assertEqual(self._verdict(tampered), Verdict.TAMPERED)

    def test_capacity_check(self) -> None:
        status = audio_workflow.check_audio_capacity(self.flac_cover, MEDIA_ID, self.private_key_pem, LSB_DEPTH)

        self.assertTrue(status.fits)
        self.assertGreater(status.capacity_bytes, status.needed_bytes)

    def test_rejects_lossy_renamed_to_flac(self) -> None:
        """Content decides, not the extension: lossy AAC named '.flac' is refused."""
        fake = _make_audio(self.folder / "lossy.flac", "-c:a", "aac", "-f", "adts")

        with self.assertRaises(AudioStegoError):
            self._encode(fake, "never.flac")
        self.assertEqual(self._verdict(fake), Verdict.PAYLOAD_MISSING)


if __name__ == "__main__":
    unittest.main()
