"""Shared verify-and-verdict logic for image and audio decoders.

Both need the same steps: check the signature, compare the hash, map to a
verdict. One tested copy here beats two hand-rolled ones.
"""

from __future__ import annotations

from crypto_payload import (
    CryptoPayloadError,
    Verdict,
    VerificationPayload,
    media_hash_matches,
    parse_and_verify,
    verdict_for_error,
)


class VerificationOutcome:
    """Result of verifying an extracted payload.

    `payload` is only set when `verdict` is AUTHENTIC.
    """

    def __init__(self, verdict: Verdict, payload: VerificationPayload | None) -> None:
        self.verdict = verdict
        self.payload = payload


def verify_extracted_payload(envelope_bytes: bytes, public_key_pem: bytes, media_bytes: bytes) -> VerificationOutcome:
    """Verify a signed envelope extracted from a stego object.

    Checks the signature first, then compares the recorded hash.
    """
    try:
        payload = parse_and_verify(envelope_bytes, public_key_pem)
    except CryptoPayloadError as exc:
        return VerificationOutcome(verdict_for_error(exc), None)

    hash_matches = media_hash_matches(media_bytes, payload.media_hash)
    verdict = verdict_for_error(None, hash_matches=hash_matches)
    return VerificationOutcome(verdict, payload if verdict == Verdict.AUTHENTIC else None)
