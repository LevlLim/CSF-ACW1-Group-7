"""Public API for the INF2005 crypto and payload core."""

from .core import (
    Verdict,
    VerificationPayload,
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
from .errors import (
    CryptoPayloadError,
    KeyMaterialError,
    PayloadIntegrityError,
    PayloadValidationError,
    SerializationFormatError,
    SignatureInvalidError,
    StartLocationError,
)

__all__ = [
    "CryptoPayloadError", "KeyMaterialError", "PayloadIntegrityError",
    "PayloadValidationError", "SerializationFormatError", "SignatureInvalidError",
    "StartLocationError", "Verdict", "VerificationPayload", "build_payload",
    "decrypt_bytes", "derive_start_location", "encrypt_bytes",
    "generate_ed25519_keypair", "media_hash_matches", "parse_and_verify",
    "sha256_hex", "sign_payload", "verdict_for_error",
]
