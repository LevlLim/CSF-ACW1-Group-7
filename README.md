# CSF-ACW1-Group-7

## Person 5: Crypto & Payload Core

This repository currently provides the shared, stateless Python library for
the INF2005 steganography project. Image and audio modules can use it to create
the verification record for **FR3: Payload generation**, sign it for **FR4:
Digital signature**, optionally encrypt it before LSB embedding, derive a
protected start location for **FR7: Variable start location**, and map failures
to **FR10: Verdict generation** outcomes.

### Assignment functional-requirement coverage

| FR | Assignment requirement | Responsible role | This library's involvement |
| --- | --- | --- | --- |
| FR1 | Image input | Person 1 | Supplies signed payload bytes for image embedding. |
| FR2 | Audio input | Person 3 | Supplies signed payload bytes for audio embedding. |
| FR3 | Payload generation | Person 5 | **Implemented:** versioned media ID, timestamp, SHA-256 hash, nonce, and safe metadata. |
| FR4 | Digital signature | Person 5 | **Implemented:** Ed25519 key generation, signing, and public-key verification. |
| FR5 | Image steganographic embedding | Person 1 | P1 embeds output bytes with image LSB replacement. |
| FR6 | Audio steganographic embedding | Person 3 | P3 embeds output bytes with audio LSB replacement. |
| FR7 | Variable start location | Person 5 + P1/P3/P2/P4 | **Implemented:** HMAC-derived location; media modules apply it during embedding/extraction. |
| FR8 | Extraction and decoding | Person 2 / Person 4 | P2/P4 extract bytes then call `parse_and_verify`. |
| FR9 | Hash verification | Person 5 + Person 2/4 | **Implemented:** SHA-256 comparison helper; P2/P4 supply the agreed stable media bytes. |
| FR10 | Verdict generation | Person 5 + Person 2/4 | **Implemented:** verdict mapper; P2/P4 display it in their workflow/GUI. |
| FR11 | Positive and negative cases | Person 6, with P1--P5 support | This library provides unit-testable crypto failure conditions. |
| FR12 | Evidence and reproducibility | Person 6, with team support | Setup and validation commands are documented below. |
| FR13 | Innovation | Person 6 | HMAC-derived secret start location and optional AES-GCM are available as possible supporting design elements. |

### Security design

- `VerificationPayload` contains `media_id`, UTC timestamp, SHA-256 media hash,
  256-bit random nonce, format version, and JSON-safe metadata.
- Canonical UTF-8 JSON is signed with Ed25519. The signed envelope can be
  verified only with its paired public key.
- Optional AES-256-GCM encrypts an envelope when confidentiality is required;
  it includes authenticated encryption rather than unauthenticated encryption.
- Start location is HMAC-SHA-256(secret, media ID, cover type, capacity, payload
  length), with a protocol-domain label. It is not stored in plaintext. Both
  encoder and decoder need the same secret and context; provide this secret via
  environment variable/KMS, never source code or a committed `.env` file.
- The library keeps no state and creates no key files. It uses safe JSON only;
  it never uses `pickle` or `eval`.

Ed25519 and SHA-256/HMAC-SHA-256 are current standard cryptography, but this
prototype is not post-quantum secure. See [EVALUATION.md](EVALUATION.md) and
[DEBUG.md](DEBUG.md) for acceptance criteria, limitations, recovery, and safe
logging rules.

### Setup and verification

Requires Python 3.11+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
```

Optional type check after installing `mypy`:

```powershell
python -m pip install mypy
python -m mypy
```

### P1--P4 integration outline

1. Hash the agreed **stable pre-embedding representation** (not an already
   changed stego file), then call `build_payload` and `sign_payload`.
2. If payload confidentiality is in scope, call `encrypt_bytes` on the signed
   envelope. Use the resulting bytes as the embedding payload and include the
   same media ID as AES-GCM associated data on decryption.
3. Call `derive_start_location` using a secret from the application’s secure
   configuration and the cover capacity in the embedding unit used by your
   module. Capacity must accommodate the exact bytes to embed.
4. On extraction, derive the same location, decrypt when enabled, then call
   `parse_and_verify`. Only after a valid signature use `media_hash_matches`.
   Catch the public errors or pass them to `verdict_for_error` for the FR10
   result for **FR10: Verdict generation**. Do not display an invalid payload
   as trusted metadata.

The image/audio teams own framing (such as a magic value and byte length) and
LSB conversion. They must agree on whether `capacity` means carrier samples,
bits, or bytes, and use that convention identically on both sides.

### Person 1: Image Encoder API

The PNG image encoder is exposed through `image_encoder` and is GUI-framework
independent:

```python
from image_encoder import (
    check_capacity,
    encode_image_file,
    resolve_header_start_channel,
    resolve_payload_start_channel,
)
```

- `encode_image_file(...)` accepts a PNG cover image, output path, signed
  payload bytes, `lsb_depth` from 1 to 8, `start_secret`, and `media_id`.
- Embedding uses row-major RGB channel slots: pixel `(0, 0)` red, green, blue,
  then pixel `(1, 0)`, and so on. Alpha is preserved and never used.
- The embedded frame is `b"CSFIMG1"` + 4-byte big-endian payload length +
  payload bytes.
- The decoder first derives a fixed locator header position with
  `media_id + ":header"` and reads `b"CSFHDR1"` + 4-byte framed length. It then
  derives the payload position with the real framed length by calling
  `resolve_payload_start_channel(...)`. Both locations use Person 5's
  `derive_start_location(...)`, `cover_type="image"`, capacity measured in RGB
  channel slots, and length measured in required RGB channel slots.
- `ImageEncodeResult` returns non-secret GUI details: output path, LSB depth,
  capacity, embedded size, and how many channel/pixel values changed.

### Public imports

```python
from crypto_payload import (
    build_payload, sign_payload, parse_and_verify, sha256_hex,
    derive_start_location, encrypt_bytes, decrypt_bytes,
    media_hash_matches, verdict_for_error,
)
```

Private keys are only for local assignment demonstration. In a real system,
private signing keys and start secrets must remain outside the repository; a
public key may be distributed for verification.
