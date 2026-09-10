# Crypto & Payload Core: Failure Handling and Telemetry

## Error taxonomy

| Exception | Meaning | Caller action / FR10 mapping |
| --- | --- | --- |
| `PayloadValidationError` | Payload fields, JSON metadata, or hash shape are invalid. | Reject before embedding; `Cannot Verify`. |
| `SerializationFormatError` | Envelope is absent, malformed, non-UTF-8, non-JSON, or structurally invalid. | Treat as `Payload Missing` when extraction has no frame; otherwise `Cannot Verify`. |
| `PayloadIntegrityError` | A signed envelope was changed or cannot be safely decoded. | Do not use its contents; `Cannot Verify`. |
| `SignatureInvalidError` | Ed25519 public-key verification failed. | Reject it; `Signature Invalid`. |
| `StartLocationError` | Secret/context/capacity cannot produce a legal location. | Retry only with the authorised correct context; `Wrong Start Location`. |
| `KeyMaterialError` | PEM/raw key input is invalid or wrong key type. | Stop the operation and re-provision key material; `Cannot Verify`. |

## Safe logging rules

Log only the UTC timestamp, operation name, exception class, non-sensitive
media identifier if policy permits it, cover type, and coarse payload length.
Never log plaintext payload content, canonical signed bytes, signature, nonce,
media hash, HMAC/start secret, private/public key material, derived start
location, or full malformed input. The library itself emits no logs; its caller
owns redacted telemetry and user-facing messages.

## Recovery paths

1. On extraction failure, retain the original stego object and record a
   redacted failure event in the application dead-letter/quarantine store; do
   not repeatedly guess locations or keys.
2. On invalid signature or hash mismatch, mark the object untrusted, preserve
   it for forensic review, and do not render its metadata as authoritative.
3. On invalid key material, re-provision from the configured environment/KMS;
   never generate a replacement key during verification because that masks the
   mismatch.
4. On insufficient cover capacity, abort before any LSB mutation and ask the
   embedding module to choose a larger cover or a smaller payload.

## Boundary rule

P1--P4 must catch only these public exceptions or use `verdict_for_error`.
They must not expose underlying cryptography exceptions, nor continue to hash
or display a payload after a signature failure.
