# Crypto & Payload Core: Acceptance Criteria

This document is the contract for the shared `crypto_payload` library.  It is
written before the implementation so that the image and audio teams can rely on
one stable, testable wire format.

## Security and design criteria

- Payload data is UTF-8 JSON only; `pickle`, `eval`, and implicit object
  deserialisation are prohibited.
- The signed payload is canonical JSON (sorted keys, compact separators). This
  makes the exact bytes covered by Ed25519 unambiguous across P1--P4.
- A payload includes `version`, `media_id`, UTC `timestamp`, SHA-256
  `media_hash`, cryptographic `nonce`, and caller-supplied JSON `metadata`.
- Signing uses Ed25519 through the audited `cryptography` package. Verification
  accepts only its paired public key. Ed25519 is a current, widely deployed
  standardised signature algorithm (FIPS 186-5); it is **not** quantum
  resistant, so this prototype must not claim post-quantum security.
- Start locations are derived with HMAC-SHA-256 from a secret, media identifier,
  cover type, capacity, and an explicit domain-separation label. The location
  is therefore neither stored in the payload nor guessable from public data
  alone. HMAC-SHA-256 is a current NIST-approved construction; it too is not
  post-quantum secure.
- Keys and start-location secrets are caller supplied (typically environment
  variables or a KMS); no key is persisted or hardcoded by this library.

## Test cases

| ID | Exact input/action | Expected outcome |
| --- | --- | --- |
| T1 | Build payload: `media_id="image-001"`, SHA-256 of `b"cover"`, metadata `{"media_type":"image"}` | Valid payload with 64-character lowercase hash and a 32-byte random nonce encoded as 64 hex characters. |
| T2 | Sign T1 with a newly generated Ed25519 private key; serialise then parse with its public key | Parsed payload equals T1 (apart from JSON ordering); verification verdict is authentic. |
| T3 | `build_payload("id", b"short", {})` | Raise `PayloadValidationError`; media hash must be exactly 32 bytes. |
| T4 | Parse `b""`, invalid UTF-8, malformed JSON, or an envelope without required fields | Raise `SerializationFormatError`; never execute input. |
| T5 | Change one base64 character in a valid signed payload before parsing | Raise `SignatureInvalidError`; never return payload data as verified. |
| T6 | Verify a valid envelope using a different public key | Raise `SignatureInvalidError`. |
| T7 | Call `derive_start_location(b"s" * 32, "image-001", "image", 1000, 200)` twice | Same integer in `[0, 800]`; changing secret or cover type gives a separately derived result. |
| T8 | Derive with capacity `199`, payload length `200`, or empty secret | Raise `StartLocationError`. |
| T9 | Compare SHA-256 for `b"cover"` with the T1 hash, then with `b"tampered"` | First result `True`; second result `False`, enabling FR10 `Authentic`/`Tampered`. |
| T10 | Request a verdict for parse, signature, hash mismatch, missing payload, wrong location, and an unexpected error | Respectively map to `PAYLOAD_MISSING`, `SIGNATURE_INVALID`, `TAMPERED`, `WRONG_START_LOCATION`, and `CANNOT_VERIFY`. |

## Performance limits

On a typical lab machine, transformation of a payload with at most 12 KiB of
canonical JSON must add no more than 100 ms for signing and 100 ms for parsing
and verification. The compact UTF-8 envelope must be no larger than 20 KiB at
that payload size. These are prototype acceptance targets, not real-time or
production guarantees.

## Verification procedure

Run `python -m unittest discover -s tests -v`. The suite must cover every test
case above, and tests may generate temporary in-memory keys only.
