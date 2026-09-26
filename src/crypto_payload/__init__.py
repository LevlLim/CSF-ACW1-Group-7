"""Public API for the INF2005 crypto and payload core."""

from .core import (
    MESSAGE_HASH_METADATA_KEY,
    Verdict,
    VerificationPayload,
    build_payload,
    decrypt_bytes,
    derive_start_location,
    encrypt_bytes,
    generate_ed25519_keypair,
    media_hash_matches,
    message_hash_hex,
    open_signed_envelope,
    parse_and_verify,
    protect_signed_envelope,
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
    "MESSAGE_HASH_METADATA_KEY", "CryptoPayloadError", "KeyMaterialError", "PayloadIntegrityError",
    "PayloadValidationError", "SerializationFormatError", "SignatureInvalidError",
    "StartLocationError", "Verdict", "VerificationPayload", "build_payload",
    "decrypt_bytes", "derive_start_location", "encrypt_bytes",
    "generate_ed25519_keypair", "media_hash_matches", "message_hash_hex", "parse_and_verify",
    "open_signed_envelope", "protect_signed_envelope", "sha256_hex", "sign_payload", "verdict_for_error",
]
