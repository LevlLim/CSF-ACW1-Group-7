"""Tests for attack_sim/video_attacks.py: every realistic attack must be caught.

These are the same attacks the Attack Sim tab runs, with the verdict each should give.
"""

from __future__ import annotations

import unittest

from attack_sim import (
    simulate_video_audio_edit,
    simulate_video_extra_track,
    simulate_video_frame_edit,
    simulate_video_reexport,
    simulate_video_wrong_key,
    simulate_video_wrong_start_location,
)
from attack_sim.models import AttackSimulationResult
from crypto_payload import Verdict
from tests.video_test_helpers import LSB_DEPTH, MEDIA_ID, SECRET, VideoTestCase

CREDENTIALS = {"lsb_depth": LSB_DEPTH, "start_secret": SECRET, "media_id": MEDIA_ID}


class VideoAttackTests(VideoTestCase):

    def _assert_caught(self, attack: AttackSimulationResult, expected: Verdict) -> None:
        self.assertEqual(attack.verdict, expected, f"{attack.attack_name}: {attack.details}")

    def test_frame_edit(self) -> None:
        """Deepfake-style: new picture, original payload-carrying audio kept."""
        attack = simulate_video_frame_edit(
            self.stego, self.folder / "frame_edit.mp4", public_key_pem=self.public_key_pem, **CREDENTIALS
        )
        self._assert_caught(attack, Verdict.TAMPERED)

    def test_audio_edit(self) -> None:
        """Dubbing-style: some sound replaced, hidden payload left intact."""
        attack = simulate_video_audio_edit(
            self.stego, self.folder / "audio_edit.mp4", public_key_pem=self.public_key_pem, **CREDENTIALS
        )
        self._assert_caught(attack, Verdict.TAMPERED)

    def test_extra_track(self) -> None:
        attack = simulate_video_extra_track(
            self.stego, self.folder / "extra_track.mp4", public_key_pem=self.public_key_pem, **CREDENTIALS
        )
        self._assert_caught(attack, Verdict.TAMPERED)

    def test_reexport(self) -> None:
        """Lossy re-encoding (editing app, social media) destroys the fragile LSB payload."""
        attack = simulate_video_reexport(
            self.stego, self.folder / "reexported.mp4", public_key_pem=self.public_key_pem, **CREDENTIALS
        )
        self._assert_caught(attack, Verdict.PAYLOAD_MISSING)

    def test_wrong_key(self) -> None:
        self._assert_caught(simulate_video_wrong_key(self.stego, **CREDENTIALS), Verdict.SIGNATURE_INVALID)

    def test_guessed_secret(self) -> None:
        attack = simulate_video_wrong_start_location(self.stego, public_key_pem=self.public_key_pem, **CREDENTIALS)
        self._assert_caught(attack, Verdict.PAYLOAD_MISSING)


if __name__ == "__main__":
    unittest.main()
