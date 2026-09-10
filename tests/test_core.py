"""Acceptance tests for the shared cryptographic payload core."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime

from crypto_payload import (
    KeyMaterialError,
    PayloadIntegrityError,
    PayloadValidationError,
    SerializationFormatError,
    SignatureInvalidError,
    StartLocationError,
    Verdict,
    build_payload,
    decrypt_bytes,
    derive_start_location,
    encrypt_bytes,
    generate_ed25519_keypair,
    media_hash_matches,
    parse_and_verify,
    sha256_hex,
    sign_payload,
    verdict_for_error,
)


class CryptoPayloadTests(unittest.TestCase):
    """Tests T1--T10 documented in EVALUATION.md."""

    def setUp(self) -> None:
        """Create ephemeral assignment-demo keys and a deterministic payload."""
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.payload = build_payload(
            "image-001",
            bytes.fromhex(sha256_hex(b"cover")),
            {"media_type": "image"},
            datetime(2026, 1, 1, tzinfo=UTC),
        )

    def test_t1_payload_schema(self) -> None:
        """A valid payload has a SHA-256 hash and random 256-bit nonce."""
        self.assertEqual(self.payload.media_hash, sha256_hex(b"cover"))
        self.assertEqual(len(self.payload.nonce), 64)
        self.assertEqual(self.payload.timestamp, "2026-01-01T00:00:00Z")

    def test_t2_round_trip_signature(self) -> None:
        """A paired Ed25519 key verifies and recovers the canonical record."""
        envelope = sign_payload(self.payload, self.private_key)
        self.assertEqual(parse_and_verify(envelope, self.public_key), self.payload)
        self.assertEqual(verdict_for_error(None, True), Verdict.AUTHENTIC)

    def test_t3_rejects_wrong_hash_length(self) -> None:
        """A non-SHA-256-length raw digest is rejected before embedding."""
        with self.assertRaises(PayloadValidationError):
            build_payload("id", b"short", {})

    def test_t4_rejects_bad_serialization(self) -> None:
        """Only valid UTF-8 JSON object envelopes are accepted."""
        for value in (b"", b"\xff", b"[]", b"{}"):
            with self.subTest(value=value), self.assertRaises(SerializationFormatError):
                parse_and_verify(value, self.public_key)

    def test_t5_detects_altered_signed_payload(self) -> None:
        """A changed signed payload is rejected as an invalid signature."""
        envelope = json.loads(sign_payload(self.payload, self.private_key))
        envelope["payload"] = envelope["payload"][:-2] + "AA"
        altered = json.dumps(envelope).encode("utf-8")
        with self.assertRaises(SignatureInvalidError):
            parse_and_verify(altered, self.public_key)

    def test_t6_rejects_wrong_public_key(self) -> None:
        """A signature cannot validate with another signer public key."""
        _, wrong_public_key = generate_ed25519_keypair()
        with self.assertRaises(SignatureInvalidError):
            parse_and_verify(sign_payload(self.payload, self.private_key), wrong_public_key)

    def test_t7_start_location_is_deterministic_and_bounded(self) -> None:
        """The HMAC-derived offset is repeatable only for identical context."""
        first = derive_start_location(b"s" * 32, "image-001", "image", 1000, 200)
        second = derive_start_location(b"s" * 32, "image-001", "image", 1000, 200)
        other = derive_start_location(b"t" * 32, "image-001", "image", 1000, 200)
        self.assertEqual(first, second)
        self.assertGreaterEqual(first, 0)
        self.assertLessEqual(first, 800)
        self.assertNotEqual(first, other)

    def test_t8_rejects_invalid_start_context(self) -> None:
        """A location cannot be derived when the payload will not fit."""
        with self.assertRaises(StartLocationError):
            derive_start_location(b"s" * 32, "image-001", "image", 199, 200)
        with self.assertRaises(StartLocationError):
            derive_start_location(b"", "image-001", "image", 1000, 200)

    def test_t9_hash_comparison(self) -> None:
        """The current media hash distinguishes original and tampered bytes."""
        self.assertTrue(media_hash_matches(b"cover", self.payload.media_hash))
        self.assertFalse(media_hash_matches(b"tampered", self.payload.media_hash))

    def test_t10_verdict_mapping(self) -> None:
        """Expected public failures map to conservative FR10 verdicts."""
        self.assertEqual(verdict_for_error(SerializationFormatError()), Verdict.PAYLOAD_MISSING)
        self.assertEqual(verdict_for_error(SignatureInvalidError()), Verdict.SIGNATURE_INVALID)
        self.assertEqual(verdict_for_error(StartLocationError()), Verdict.WRONG_START_LOCATION)
        self.assertEqual(verdict_for_error(PayloadValidationError()), Verdict.CANNOT_VERIFY)
        self.assertEqual(verdict_for_error(None, False), Verdict.TAMPERED)

    def test_aes_gcm_confidentiality_and_integrity(self) -> None:
        """AES-GCM round trips and detects wrong associated data."""
        key = b"k" * 32
        encrypted = encrypt_bytes(b"secret signed envelope", key, b"image-001")
        self.assertEqual(decrypt_bytes(encrypted, key, b"image-001"), b"secret signed envelope")
        with self.assertRaises(PayloadIntegrityError):
            decrypt_bytes(encrypted, key, b"different-id")
        with self.assertRaises(KeyMaterialError):
            encrypt_bytes(b"x", b"short")


if __name__ == "__main__":
    unittest.main()
