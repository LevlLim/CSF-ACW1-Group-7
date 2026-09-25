# Innovation (FR13)

**What:** the image payload begins at a pixel selected with the mouse. Its
locator header is placed using HMAC-SHA-256 over a shared secret, media ID,
cover type and capacity. The header records the selected payload channel, and
the same pixel is included in the digitally signed payload metadata so the
decoder can recover and verify it.

**Why it's useful:** an attacker who has the stego file but not the secret
cannot locate the header needed to recover the clicked payload position. A
modified header either points to invalid framed data or disagrees with the
signed start pixel. This directly answers the assignment's start-location
selection, recovery and tamper-detection requirements.

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
