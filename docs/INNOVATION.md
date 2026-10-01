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

**Video cover object (optional challenge):**

**What:** MP4 video as a third cover object. The signed payload is hidden in
the video's audio track using the team's audio LSB code, while the picture is
copied without re-encoding. The audio is saved as lossless FLAC so the hidden
bits survive.

**Why it's useful:** one SHA-256 fingerprint covers both the picture (its
stream hash) and the audio, so a swapped picture with the original audio kept
is still detected, which an audio-only check would miss. The decoder also
checks the track layout and the signed file details, and the encoder verifies
its own output before saving. Six attack simulations confirm each check.

**Limitations:**
- The video must have an audio track, and clips are limited to 60 seconds.
- Any lossy re-export (editing apps, social media) destroys the payload.
- The stego file is larger because the audio is stored as FLAC.
- AES encryption is not offered for video.
