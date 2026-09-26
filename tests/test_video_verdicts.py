"""Tests for the video encoder and decoder: what gets embedded, and which verdict comes back.

Attacks on a stego video (tampering, wrong key, re-encoding...) are in test_video_attacks.py.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from audio_stego.common import load_wav_pcm
from crypto_payload import Verdict
from tests.video_test_helpers import LSB_DEPTH, MEDIA_ID, SECRET, VideoTestCase, make_test_video
from video_decoder import VideoDecodeResult, decode_video_file
from video_stego import VideoStegoError, encode_video_file
from video_stego.common import MAX_DURATION_SECONDS
from video_stego.video_processing import extract_audio, probe_streams


class VideoVerdictTests(VideoTestCase):

    def _decode(self, video: Path, secret: bytes = SECRET) -> VideoDecodeResult:
        return decode_video_file(
            video, lsb_depth=LSB_DEPTH, start_secret=secret, media_id=MEDIA_ID, public_key_pem=self.public_key_pem
        )

    def _encode(self, cover: Path) -> None:
        encode_video_file(
            cover, self.folder / "encoded.mp4", media_id=MEDIA_ID,
            private_key_pem=self.private_key_pem, start_secret=SECRET, lsb_depth=LSB_DEPTH,
        )

    def test_only_lsbs_change(self) -> None:
        self.assertEqual(probe_streams(self.stego)[0].sha256, probe_streams(self.cover)[0].sha256)

        cover_wav, stego_wav = self.folder / "cover.wav", self.folder / "stego.wav"
        extract_audio(self.cover, cover_wav)
        extract_audio(self.stego, stego_wav)
        cover_samples = load_wav_pcm(cover_wav).samples
        stego_samples = load_wav_pcm(stego_wav).samples

        changed = [i for i, (a, b) in enumerate(zip(cover_samples, stego_samples)) if a != b]
        self.assertGreater(len(changed), 0)
        high_bits = ~((1 << LSB_DEPTH) - 1)
        for i in changed:
            self.assertEqual(cover_samples[i] & high_bits, stego_samples[i] & high_bits)

    def test_authentic(self) -> None:
        result = self._decode(self.stego)

        self.assertEqual(result.verdict, Verdict.AUTHENTIC)
        assert result.payload is not None
        self.assertEqual(result.payload.metadata["note"], "hello from video")
        self.assertEqual(result.payload.metadata["cover_type"], "video")

    def test_wrong_secret(self) -> None:
        result = self._decode(self.stego, secret=b"wrong-secret")

        self.assertEqual(result.verdict, Verdict.PAYLOAD_MISSING)
        self.assertIsNone(result.payload, "a failed verification must not return the payload")
        self.assertIn("secret/media ID is wrong", "\n".join(result.explanation))

    def test_plain_cover(self) -> None:
        self.assertEqual(self._decode(self.cover).verdict, Verdict.PAYLOAD_MISSING)

    def test_non_video_file(self) -> None:
        fake_video = self.folder / "not_a_video.mp4"
        fake_video.write_text("this is not a video")

        self.assertEqual(self._decode(fake_video).verdict, Verdict.CANNOT_VERIFY)

    def test_no_audio(self) -> None:
        silent = make_test_video(self.folder / "silent.mp4", with_audio=False)

        with self.assertRaisesRegex(VideoStegoError, "no audio track"):
            self._encode(silent)

    def test_too_long(self) -> None:
        too_long = make_test_video(self.folder / "long.mp4", seconds=MAX_DURATION_SECONDS + 3)

        with self.assertRaisesRegex(VideoStegoError, "maximum"):
            self._encode(too_long)


if __name__ == "__main__":
    unittest.main()
