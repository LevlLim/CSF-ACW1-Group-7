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

**Payload confidentiality layer:**
The Image and Audio encoder checkboxes encrypt the signed envelope with
AES-256-GCM before embedding. A domain-separated HMAC derives the key from the
shared secret, media ID and cover type, and the decoder automatically supports
both encrypted and earlier signed-only envelopes. This provides confidentiality
and authenticated encryption for the custom-payload case. A weak shared secret
still permits guessing attacks, so the demo must use a strong secret and explain
that production deployment would use a password KDF or managed key.
