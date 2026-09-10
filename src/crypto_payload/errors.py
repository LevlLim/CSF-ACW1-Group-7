"""Public exceptions for safe, caller-facing failure handling."""


class CryptoPayloadError(Exception):
    """Base exception for expected shared-library failures."""


class PayloadValidationError(CryptoPayloadError):
    """Raised when a payload field or metadata value violates the schema."""


class SerializationFormatError(CryptoPayloadError):
    """Raised when untrusted bytes are not a valid expected JSON structure."""


class PayloadIntegrityError(CryptoPayloadError):
    """Raised when an encrypted envelope cannot be authenticated or decoded."""


class SignatureInvalidError(CryptoPayloadError):
    """Raised when an Ed25519 signature does not verify."""


class StartLocationError(CryptoPayloadError):
    """Raised when a keyed start location cannot fit in the cover capacity."""


class KeyMaterialError(CryptoPayloadError):
    """Raised when key material has an invalid length, type, or encoding."""
