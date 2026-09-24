# Innovation (FR13)

**What:** the payload start location is not fixed (e.g. top-left corner) and
is not stored anywhere in the cover object. It is derived with
HMAC-SHA-256 from a shared secret, the media ID, the cover type, the cover's
capacity, and the payload length — implemented in
`crypto_payload.derive_start_location` (`src/crypto_payload/core.py`) and used
by the image encoder/decoder via `resolve_header_start_channel` /
`resolve_payload_start_channel` (`src/image_encoder/encoder.py`).

**Why it's useful:** an attacker who has the stego file but not the secret
cannot locate the payload to remove, corrupt, or replay it — guessing is
infeasible (256-bit HMAC output space) and the location changes whenever the
media ID, cover, or payload length changes, so it isn't reusable across
files. This directly answers the assignment's start-location security
requirement (Criterion 1) rather than just picking "a location other than
top-left."

**Limitations:**
- Anyone who obtains the shared secret can locate and read every payload
  encoded with it — the secret must be distributed out of band (env
  var/KMS), never hardcoded, per `DEBUG.md`.
- HMAC-SHA-256 is not post-quantum secure (neither is the Ed25519 signature
  used for FR4); this is a prototype-level defense, not a production
  guarantee.
- The derived location is only as strong as the secret's entropy — a weak,
  guessable secret undermines the whole scheme.

**Optional second layer (not yet wired into the GUI):**
`crypto_payload.encrypt_bytes`/`decrypt_bytes` (AES-256-GCM) can encrypt the
signed envelope before embedding, adding confidentiality on top of the
integrity/authenticity the signature already provides — useful for the
"custom payload" case in the test matrix, which the spec asks to protect for
confidentiality as well as integrity.
