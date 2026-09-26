"""Tests for video_stego/video_processing.py: the ffmpeg helpers on their own."""

from __future__ import annotations

import unittest

from PIL import Image

from audio_stego.common import load_wav_pcm
from tests.video_test_helpers import VideoTestCase, make_test_video
from video_stego.video_processing import (
    VideoStegoError,
    extract_audio,
    extract_thumbnail,
    probe_streams,
    remux,
)


class VideoProcessingTests(VideoTestCase):

    def test_probe_streams(self) -> None:
        streams = probe_streams(self.cover)

        self.assertEqual([stream.kind for stream in streams], ["v", "a"])
        self.assertEqual([stream.index for stream in streams], [0, 1])
        for stream in streams:
            self.assertEqual(len(stream.sha256), 32)

    def test_remux_is_lossless(self) -> None:
        """The core promise of the design: video untouched, audio bit-exact."""
        original_wav = self.folder / "original.wav"
        remuxed_video = self.folder / "remuxed.mp4"
        roundtrip_wav = self.folder / "roundtrip.wav"

        extract_audio(self.cover, original_wav)
        remux(self.cover, original_wav, remuxed_video)
        extract_audio(remuxed_video, roundtrip_wav)

        remuxed_streams = probe_streams(remuxed_video)
        self.assertEqual([stream.kind for stream in remuxed_streams], ["v", "a"])
        self.assertEqual(remuxed_streams[0].sha256, probe_streams(self.cover)[0].sha256)
        self.assertEqual(load_wav_pcm(original_wav).samples, load_wav_pcm(roundtrip_wav).samples)

    def test_rejects_non_video(self) -> None:
        fake_video = self.folder / "fake.mp4"
        fake_video.write_text("this is not a video")

        with self.assertRaises(VideoStegoError):
            probe_streams(fake_video)
        with self.assertRaises(VideoStegoError):
            extract_audio(fake_video, self.folder / "fake.wav")

    def test_rejects_silent_video(self) -> None:
        silent = make_test_video(self.folder / "silent.mp4", with_audio=False)
        self.assertEqual([stream.kind for stream in probe_streams(silent)], ["v"])

        with self.assertRaises(VideoStegoError):
            extract_audio(silent, self.folder / "silent.wav")

    def test_length_cap(self) -> None:
        capped_wav = self.folder / "capped.wav"

        extract_audio(self.cover, capped_wav, max_seconds=1)

        wav = load_wav_pcm(capped_wav)
        self.assertAlmostEqual(wav.frame_count / wav.frame_rate, 1.0, places=2)

    def test_output_names(self) -> None:
        """Regression test: without "-f" / "-update 1", ffmpeg guessed formats
        from the extension and treated "%d" in a name as a numbered pattern."""
        no_extension_wav = self.folder / "audio_no_extension"
        percent_png = self.folder / "thumb%d.png"
        no_extension_png = self.folder / "thumb_no_extension"

        extract_audio(self.cover, no_extension_wav)
        extract_thumbnail(self.cover, percent_png)
        extract_thumbnail(self.cover, no_extension_png)

        self.assertGreater(len(load_wav_pcm(no_extension_wav).samples), 0)
        for thumbnail in (percent_png, no_extension_png):
            self.assertTrue(thumbnail.exists(), f"{thumbnail.name} was not created")
            with Image.open(thumbnail) as image:
                self.assertEqual(image.format, "PNG")
                self.assertEqual(image.size, (160, 120))


if __name__ == "__main__":
    unittest.main()
