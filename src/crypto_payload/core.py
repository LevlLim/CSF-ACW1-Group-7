"""Stateless cryptographic payload transformations for image and audio modules."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import (
    KeyMaterialError,
    PayloadIntegrityError,
    PayloadValidationError,
    SerializationFormatError,
    SignatureInvalidError,
    StartLocationError,
)

_PAYLOAD_VERSION = 1
_AES_GCM_NONCE_BYTES = 12
_AES_256_KEY_BYTES = 32
_START_LOCATION_DOMAIN = b"INF2005-CSF-START-LOCATION-V1\x00"


class Verdict(StrEnum):
    """User-facing FR10 outcomes exposed to image and audio workflows."""

    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"


@dataclass(frozen=True, slots=True)
class VerificationPayload:
    """The compact, signed verification record embedded by P1 or P3.

    Attributes are primitives only so JSON serialisation remains safe and
    portable. ``media_hash`` is a lowercase SHA-256 hexadecimal digest.
    """

    version: int
    media_id: str
    timestamp: str
    media_hash: str
    nonce: str
    metadata: dict[str, Any]


def sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 digest for bytes.

    SHA-256 is used for the assignment's media-integrity fingerprint.
    """
    return hashlib.sha256(data).hexdigest()


def build_payload(
    media_id: str,
    media_hash: bytes,
    metadata: Mapping[str, Any],
    timestamp: datetime | None = None,
) -> VerificationPayload:
    """Create a schema-validated payload with a cryptographic random nonce.

    Args:
        media_id: Non-empty caller identifier for the original cover object.
        media_hash: Exactly 32 raw bytes from SHA-256 of the agreed stable media
            representation.
        metadata: JSON-compatible, team-defined contextual data.
        timestamp: Optional UTC-aware timestamp; current UTC time is used when
            omitted.

    Raises:
        PayloadValidationError: If an identifier, hash, timestamp, or metadata
            value cannot be represented safely in the fixed payload schema.
    """
    if not media_id or not isinstance(media_id, str):
        raise PayloadValidationError("media_id must be a non-empty string")
    if len(media_hash) != 32:
        raise PayloadValidationError("media_hash must be a 32-byte SHA-256 digest")
    when = timestamp or datetime.now(UTC)
    if when.tzinfo is None:
        raise PayloadValidationError("timestamp must be timezone-aware")
    payload = VerificationPayload(
        version=_PAYLOAD_VERSION,
        media_id=media_id,
        timestamp=when.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        media_hash=media_hash.hex(),
        nonce=secrets.token_hex(32),
        metadata=dict(metadata),
    )
    _canonical_payload_bytes(payload)
    return payload


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate an in-memory Ed25519 PEM private/public key pair.

    The caller must store the private PEM in an environment secret or KMS; this
    pure function neither writes files nor retains key material.
    """
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_payload(payload: VerificationPayload, private_key_pem: bytes) -> bytes:
    """Return a compact JSON envelope signed with Ed25519.

    Canonical JSON bytes are signed, then base64url encoded alongside the
    signature. Ed25519 provides integrity and signer authentication, not
    confidentiality; call ``encrypt_bytes`` if the embedded record is secret.

    Raises:
        PayloadValidationError: If the payload is invalid.
        KeyMaterialError: If the private PEM is invalid or not Ed25519.
    """
    payload_bytes = _canonical_payload_bytes(payload)
    key = _load_private_key(private_key_pem)
    envelope = {
        "payload": _b64encode(payload_bytes),
        "signature": _b64encode(key.sign(payload_bytes)),
        "version": _PAYLOAD_VERSION,
    }
    return _canonical_json_bytes(envelope)


def parse_and_verify(envelope_bytes: bytes, public_key_pem: bytes) -> VerificationPayload:
    """Safely parse and verify an Ed25519 signed payload envelope.

    Validation occurs only after signature verification, so an invalid signature
    never yields a trusted payload object.

    Raises:
        SerializationFormatError: If the outer or inner JSON is malformed.
        SignatureInvalidError: If public-key verification fails.
        PayloadValidationError: If a correctly signed payload violates schema.
        KeyMaterialError: If the public PEM is invalid or not Ed25519.
    """
    envelope = _load_json_object(envelope_bytes)
    if set(envelope) != {"payload", "signature", "version"} or envelope["version"] != _PAYLOAD_VERSION:
        raise SerializationFormatError("unexpected signed envelope structure")
    payload_bytes = _b64decode(envelope["payload"])
    signature = _b64decode(envelope["signature"])
    key = _load_public_key(public_key_pem)
    try:
        key.verify(signature, payload_bytes)
    except InvalidSignature as exc:
        raise SignatureInvalidError("payload signature verification failed") from exc
    return _payload_from_json(payload_bytes)


def encrypt_bytes(plaintext: bytes, encryption_key: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt bytes using AES-256-GCM with a fresh 96-bit nonce.

    AES-GCM is authenticated encryption: modification or wrong key/AAD is
    detected in ``decrypt_bytes``. The returned JSON envelope includes nonce
    and ciphertext, never the key.

    Raises:
        KeyMaterialError: If ``encryption_key`` is not exactly 32 bytes.
    """
    _validate_aes_key(encryption_key)
    nonce = secrets.token_bytes(_AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, associated_data)
    return _canonical_json_bytes({"ciphertext": _b64encode(ciphertext), "nonce": _b64encode(nonce), "version": 1})


def decrypt_bytes(envelope_bytes: bytes, encryption_key: bytes, associated_data: bytes = b"") -> bytes:
    """Authenticate and decrypt an AES-256-GCM envelope.

    Raises:
        SerializationFormatError: If the envelope is malformed.
        KeyMaterialError: If the AES key is not 32 bytes.
        PayloadIntegrityError: If authentication fails, including wrong key/AAD.
    """
    _validate_aes_key(encryption_key)
    envelope = _load_json_object(envelope_bytes)
    if set(envelope) != {"ciphertext", "nonce", "version"} or envelope["version"] != 1:
        raise SerializationFormatError("unexpected encryption envelope structure")
    nonce = _b64decode(envelope["nonce"])
    if len(nonce) != _AES_GCM_NONCE_BYTES:
        raise SerializationFormatError("AES-GCM nonce must be 12 bytes")
    try:
        return AESGCM(encryption_key).decrypt(nonce, _b64decode(envelope["ciphertext"]), associated_data)
    except InvalidTag as exc:
        raise PayloadIntegrityError("AES-GCM authentication failed") from exc


def derive_start_location(secret: bytes, media_id: str, cover_type: str, capacity: int, payload_length: int) -> int:
    """Derive a deterministic, secret-bound legal LSB start offset.

    HMAC-SHA-256 binds the result to the media ID, cover type, and capacity;
    domain separation prevents reuse for another protocol. Both encoder and
    decoder must use the same secret and context. ``capacity`` and
    ``payload_length`` are measured in the embedding module's common units.

    Raises:
        StartLocationError: If inputs are empty, unsupported, or cannot fit.
    """
    if not secret or not media_id or cover_type not in {"image", "audio"}:
        raise StartLocationError("secret, media_id, and supported cover_type are required")
    if capacity < 0 or payload_length < 0 or payload_length > capacity:
        raise StartLocationError("payload does not fit within cover capacity")
    available_starts = capacity - payload_length + 1
    context = f"{media_id}\x00{cover_type}\x00{capacity}\x00{payload_length}".encode("utf-8")
    value = int.from_bytes(hmac.digest(secret, _START_LOCATION_DOMAIN + context, "sha256"), "big")
    return value % available_starts


def media_hash_matches(media_bytes: bytes, expected_hash_hex: str) -> bool:
    """Compare a recomputed SHA-256 digest in constant time for FR9.

    Returns ``False`` for malformed expected hashes rather than raising, making
    the normal verification path safe for untrusted extracted payloads.
    """
    if len(expected_hash_hex) != 64:
        return False
    try:
        bytes.fromhex(expected_hash_hex)
    except ValueError:
        return False
    return hmac.compare_digest(sha256_hex(media_bytes), expected_hash_hex)


def verdict_for_error(error: Exception | None, hash_matches: bool | None = None) -> Verdict:
    """Convert a verified outcome or public failure into the FR10 verdict.

    Args:
        error: ``None`` after successful extraction/verification, otherwise a
            caught public library exception.
        hash_matches: Media hash comparison result after valid signature.

    Returns:
        A conservative verdict; unexpected errors never become authentic.
    """
    if error is None:
        return Verdict.AUTHENTIC if hash_matches is True else Verdict.TAMPERED
    if isinstance(error, SignatureInvalidError):
        return Verdict.SIGNATURE_INVALID
    if isinstance(error, StartLocationError):
        return Verdict.WRONG_START_LOCATION
    if isinstance(error, SerializationFormatError):
        return Verdict.PAYLOAD_MISSING
    return Verdict.CANNOT_VERIFY


def _canonical_payload_bytes(payload: VerificationPayload) -> bytes:
    """Validate a payload and return its deterministic UTF-8 JSON bytes."""
    if payload.version != _PAYLOAD_VERSION or not payload.media_id:
        raise PayloadValidationError("unsupported payload version or empty media_id")
    if len(payload.media_hash) != 64:
        raise PayloadValidationError("media_hash must be 64 hexadecimal characters")
    try:
        if len(bytes.fromhex(payload.media_hash)) != 32:
            raise ValueError
        if len(bytes.fromhex(payload.nonce)) != 32:
            raise ValueError
        parsed_time = datetime.fromisoformat(payload.timestamp.replace("Z", "+00:00"))
        if parsed_time.tzinfo is None:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise PayloadValidationError("invalid hash, nonce, or timestamp") from exc
    return _canonical_json_bytes(asdict(payload))


def _payload_from_json(payload_bytes: bytes) -> VerificationPayload:
    """Convert a validated inner JSON object to its immutable payload record."""
    data = _load_json_object(payload_bytes)
    required = {"version", "media_id", "timestamp", "media_hash", "nonce", "metadata"}
    if set(data) != required or not isinstance(data["metadata"], dict):
        raise SerializationFormatError("unexpected payload structure")
    payload = VerificationPayload(**data)
    _canonical_payload_bytes(payload)
    return payload


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Encode JSON with deterministic separators and key ordering."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PayloadValidationError("value must be JSON serialisable") from exc


def _load_json_object(raw: bytes) -> dict[str, Any]:
    """Decode only UTF-8 JSON object bytes, never executable object formats."""
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationFormatError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise SerializationFormatError("JSON value must be an object")
    return value


def _b64encode(value: bytes) -> str:
    """Return URL-safe base64 text without changing cryptographic bytes."""
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: Any) -> bytes:
    """Strictly decode URL-safe base64 supplied by an untrusted envelope."""
    if not isinstance(value, str):
        raise SerializationFormatError("base64 field must be text")
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise SerializationFormatError("invalid base64 field") from exc


def _load_private_key(private_key_pem: bytes) -> Ed25519PrivateKey:
    """Load and type-check a PEM private key without persisting it."""
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise KeyMaterialError("invalid private key PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyMaterialError("private key must be Ed25519")
    return key


def _load_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    """Load and type-check a PEM public key without persisting it."""
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise KeyMaterialError("invalid public key PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KeyMaterialError("public key must be Ed25519")
    return key


def _validate_aes_key(encryption_key: bytes) -> None:
    """Reject non-AES-256 keys before calling the AEAD primitive."""
    if len(encryption_key) != _AES_256_KEY_BYTES:
        raise KeyMaterialError("AES-256-GCM key must be exactly 32 bytes")
