"""
Tests for the main image and verification workflows.

Flow:
1. Create a cover file.
2. Build and sign the payload.
3. Check if the payload fits.
4. Embed the payload into the image.
5. Verify the extracted payload and check the final verdict.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from crypto_payload import Verdict, build_payload, generate_ed25519_keypair, sign_payload
from workflows import image_workflow
from workflows.verification import verify_extracted_payload


def _make_cover_png(directory: Path) -> Path:
    """Create a test image large enough to hold a signed payload."""

    cover = directory / "cover.png"

    Image.new(
        "RGBA",
        (64, 64),
        (100, 150, 200, 255),
    ).save(cover)

    return cover


def _build_test_envelope(media_id: str, media_bytes: bytes, private_key_pem: bytes) -> bytes:
    """Build a signed envelope directly from crypto_payload, bypassing
    image_workflow's image-specific (masked-pixel) hashing — these tests
    exercise the generic verify_extracted_payload logic against arbitrary
    bytes, not PNG-specific behaviour.
    """
    media_hash = hashlib.sha256(media_bytes).digest()
    payload = build_payload(media_id, media_hash, {})
    return sign_payload(payload, private_key_pem)


class ImageWorkflowTests(unittest.TestCase):
    """Tests for the image embedding and decoding workflow."""

    def test_build_sign_check_and_encode_round_trip(self) -> None:
        # Generate keys for signing the payload.
        private_pem, _public_pem = generate_ed25519_keypair()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            # Create the cover image and output path.
            cover = _make_cover_png(tmp_dir)
            stego = tmp_dir / "stego.png"

            # Build and sign the payload.
            envelope = image_workflow.build_signed_envelope(
                cover,
                "img-001",
                "hello",
                private_pem,
                lsb_depth=4,
            )

            # Check if the payload fits in the image.
            status = image_workflow.check_image_capacity(
                cover,
                envelope,
                lsb_depth=4,
            )

            self.assertTrue(status.fits)
            self.assertGreater(status.needed_bits, 0)

            self.assertEqual(
                status.capacity_bits,
                image_workflow.capacity_bits(64, 64, 4),
            )

            # Embed the signed payload into the image.
            result = image_workflow.encode_image(
                cover,
                stego,
                envelope,
                4,
                b"a-secret",
                "img-001",
            )

            self.assertEqual(result.stego_path, stego)
            self.assertTrue(stego.exists())

    def test_check_image_capacity_reports_when_payload_does_not_fit(
        self,
    ) -> None:
        private_pem, _public_pem = generate_ed25519_keypair()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            # Create a very small image with limited capacity.
            cover = tmp_dir / "tiny.png"

            Image.new(
                "RGBA",
                (2, 2),
                (10, 10, 10, 255),
            ).save(cover)

            envelope = image_workflow.build_signed_envelope(
                cover,
                "img-002",
                "a fairly long note",
                private_pem,
                lsb_depth=1,
            )

            # Check that the payload does not fit.
            status = image_workflow.check_image_capacity(
                cover,
                envelope,
                lsb_depth=1,
            )

            self.assertFalse(status.fits)

    def test_full_round_trip_is_authentic(self) -> None:
        """Regression test: build_signed_envelope's cover hash must use the
        same masking convention image_decoder expects, or an untouched
        round trip would incorrectly come back as Tampered.
        """
        private_pem, public_pem = generate_ed25519_keypair()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            cover = _make_cover_png(tmp_dir)
            stego = tmp_dir / "stego.png"

            envelope = image_workflow.build_signed_envelope(cover, "img-006", "hello", private_pem, lsb_depth=2)
            image_workflow.encode_image(cover, stego, envelope, 2, b"a-secret", "img-006")

            result = image_workflow.decode_image(stego, 2, b"a-secret", "img-006", public_pem)

        self.assertEqual(result.verdict, Verdict.AUTHENTIC)
        self.assertIsNotNone(result.payload)

    def test_full_round_trip_detects_wrong_secret(self) -> None:
        private_pem, public_pem = generate_ed25519_keypair()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            cover = _make_cover_png(tmp_dir)
            stego = tmp_dir / "stego.png"

            envelope = image_workflow.build_signed_envelope(cover, "img-007", "hello", private_pem, lsb_depth=2)
            image_workflow.encode_image(cover, stego, envelope, 2, b"correct-secret", "img-007")

            result = image_workflow.decode_image(stego, 2, b"wrong-secret", "img-007", public_pem)

        self.assertNotEqual(result.verdict, Verdict.AUTHENTIC)
        self.assertIsNone(result.payload)


class VerificationWorkflowTests(unittest.TestCase):
    """Tests for verifying authentic and invalid payloads."""

    def test_authentic_payload_is_reported_with_matching_hash(self) -> None:
        private_pem, public_pem = generate_ed25519_keypair()

        # Both sides use the same original media data.
        media_bytes = b"the media bytes both sides agree on"
        envelope = _build_test_envelope("img-003", media_bytes, private_pem)

        # Verify using the correct public key and matching media.
        outcome = verify_extracted_payload(
            envelope,
            public_pem,
            media_bytes,
        )

        self.assertEqual(outcome.verdict, Verdict.AUTHENTIC)
        self.assertIsNotNone(outcome.payload)

    def test_tampered_media_yields_tampered_verdict_without_payload(
        self,
    ) -> None:
        private_pem, public_pem = generate_ed25519_keypair()
        envelope = _build_test_envelope("img-004", b"original bytes", private_pem)

        # Verify using modified media data.
        outcome = verify_extracted_payload(
            envelope,
            public_pem,
            b"different bytes now",
        )

        self.assertEqual(outcome.verdict, Verdict.TAMPERED)
        self.assertIsNone(outcome.payload)

    def test_wrong_public_key_yields_signature_invalid(self) -> None:
        private_pem, _public_pem = generate_ed25519_keypair()

        # Generate a different key pair to simulate the wrong verifier key.
        _other_private_pem, other_public_pem = generate_ed25519_keypair()

        media_bytes = b"media bytes"
        envelope = _build_test_envelope("img-005", media_bytes, private_pem)

        # Verify using the wrong public key.
        outcome = verify_extracted_payload(
            envelope,
            other_public_pem,
            media_bytes,
        )

        self.assertEqual(outcome.verdict, Verdict.SIGNATURE_INVALID)
        self.assertIsNone(outcome.payload)


if __name__ == "__main__":
    unittest.main()
