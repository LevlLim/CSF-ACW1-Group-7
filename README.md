# CSF-ACW1-Group-7

### Assignment functional-requirement coverage

| FR | Assignment requirement | Responsible role | Implementation status |
| --- | --- | --- | --- |
| FR1 | Image input | Person 1 | **Implemented:** Accepts and validates PNG cover/stego images while preserving alpha. |
| FR2 | Audio input | Person 3 | **Implemented:** Accepts PCM WAV and lossless FLAC input through the audio workflow. |
| FR3 | Payload generation | Person 5 | **Implemented:** versioned media ID, timestamp, SHA-256 hash, nonce, and safe metadata. |
| FR4 | Digital signature | Person 5 | **Implemented:** Ed25519 key generation, signing, and public-key verification. |
| FR5 | Image steganographic embedding | Person 1 | **Implemented:** P1 embeds output bytes with image LSB replacement. |
| FR6 | Audio steganographic embedding | Person 3 | **Implemented:** P3 embeds output bytes with audio LSB replacement. |
| FR7 | Variable start location | Person 5 + P1/P3/P2/P4 | **Implemented:** HMAC-derived locator positions; image also supports a mouse-selected payload start pixel recovered by the decoder. |
| FR8 | Extraction and decoding | Person 2 / Person 4 | **Implemented:** P2/P4 extract bytes then call `parse_and_verify`. |
| FR9 | Hash verification | Person 5 + Person 2/4 | **Implemented:** SHA-256 comparison helper; P2/P4 supply the agreed stable media bytes. |
| FR10 | Verdict generation | Person 5 + Person 2/4 | **Implemented:** verdict mapper; P2/P4 display it in their workflow/GUI. |
| FR11 | Positive and negative cases | Person 6, with P1--P5 support | **Implemented:** This library provides unit-testable crypto failure conditions. |
| FR12 | Evidence and reproducibility | Person 6, with team support | **Implemented:** setup instructions, reproducible samples, verification settings and test-evidence screenshots are included. |
| FR13 | Innovation | Person 6 | **Implemented:** HMAC-derived start locations, selectable AES-GCM payload confidentiality, an Attack Simulation module, and video cover-object support. |

### Setup and verification

Requires Python 3.11+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
python -m app
```

The automated suite should finish with `OK`. The two standalone decoder case
scripts may also be run when reproducing the mandatory positive and negative
cases:

```powershell
python tests/test_image_decoder.py
python tests/test_audio_decoder.py
```

The GUI accepts a message typed directly into the editor or loaded from a
UTF-8 `.txt` file. Image covers must be PNG. The mandatory audio workflow uses
PCM WAV; the application also supports lossless FLAC conversion. Video and
Attack Simulation are optional extensions.

Optional type check after installing `mypy`:

```powershell
python -m pip install mypy
python -m mypy
```

## Person 1: Image Encoder API

This repository provides the PNG image-encoder API for **FR1: Image input**,
**FR5: Image steganographic embedding**, and **FR7: Variable start location**.

### Public imports

The PNG image encoder is exposed through `image_encoder` and is GUI-framework
independent:

```python
from image_encoder import (
    check_capacity,
    encode_image_file,
    resolve_header_start_channel,
    resolve_payload_start_channel,
    stable_image_hash,
)
```

### Encoder design

- `encode_image_file(...)` accepts a PNG cover image, output path, signed
  payload bytes, `lsb_depth` from 1 to 8, `start_secret`, `media_id`, and an
  optional mouse-selected `start_pixel`.
- `stable_image_hash(image_path, lsb_depth)` returns a raw 32-byte digest of a
  canonical representation containing dimensions, mode, alpha and RGB values
  after zeroing the selected RGB LSB bits. Cover and stego digests match after
  embedding, while alpha or structural tampering changes the digest.
- Embedding uses row-major RGB channel slots: pixel `(0, 0)` red, green, blue,
  then pixel `(1, 0)`, and so on. Alpha is preserved and never used.
- The embedded frame is `b"CSFIMG1"` + 4-byte big-endian payload length +
  payload bytes.
- The decoder derives a protected locator position with `media_id + ":header"`
  and reads `b"CSFHDR2"`, the framed length, and the selected payload channel.
  The locator position uses Person 5's HMAC-based `derive_start_location(...)`;
  the clicked pixel is also included in the signed payload metadata so the
  recovered location can be checked after signature verification.
- Optional AES-256-GCM payload confidentiality is applied by
  `workflows.image_workflow.build_signed_envelope(...)` before the resulting
  protected bytes are passed to `encode_image_file(...)`.
- `ImageEncodeResult` returns non-secret GUI details: output path, LSB depth,
  capacity, embedded size, and how many channel/pixel values changed.

## Person 2: Image Decoder & Verification

This repository provides the PNG image-decoder and verification API for
**FR8: Extraction and decoding**, **FR9: Hash verification**, and
**FR10: Verdict generation**.

### Public imports

The PNG decoder is exposed through `image_decoder` and is independent of the
GUI toolkit:

```python
from image_decoder import ImageDecodeResult, decode_image_file
```

### Decoder and verification design

- `decode_image_file(...)` accepts a stego PNG, `lsb_depth`, start-location
  secret, media ID, and signer public-key PEM.
- It derives the locator-header position using the shared
  `derive_start_location(...)` protocol, recovers `b"CSFHDR2"`, the framed
  length and clicked start channel, then extracts the `b"CSFIMG1"` payload.
- The extracted envelope is automatically decrypted when it is AES-GCM
  protected, then passed to `parse_and_verify(...)`; only a successfully
  verified payload is used for the subsequent media check.
- The decoder masks the selected RGB LSBs, recomputes `stable_image_hash(...)`,
  and compares it in constant time with the signed media hash for FR9.
- `ImageDecodeResult` returns the FR10 `Verdict`, a verified
  `VerificationPayload` when authentic, and a safe public error otherwise.
- `tests/test_image_decoder.py` covers short and large authentic payloads plus
  altered media, a wrong start secret, and a cover with no hidden payload.

## Person 3: Audio Encoder

This repository provides the WAV audio-encoder API for **FR2: Audio input**,
**FR6: Audio steganographic embedding**, and **FR7: Variable start location**.

### Public imports

The WAV encoder is exposed through `audio_stego`; the workflow wrapper is used
by the GUI:

```python
from audio_stego import AudioEncodeResult, encode_audio_file
from audio_stego.locations import (
    HEADER_MAGIC,
    resolve_header_start_sample,
    resolve_payload_start_sample,
)
from workflows.audio_workflow import check_audio_capacity, encode_audio
```

### Encoder design

- Input is uncompressed 8-bit or 16-bit PCM WAV. The loader preserves channel
  count, sample width, frame rate, and frame count when saving the stego WAV.
  `workflows.audio_workflow.encode_audio(...)` additionally accepts FLAC
  input/output, transparently converting to/from WAV around this core logic.
- `create_signed_audio_payload(...)` masks the selected sample LSBs to create
  stable audio bytes containing the PCM properties and samples, hashes them
  with SHA-256, builds the payload, and signs it with Ed25519.
- The signed envelope is framed as `b"CSF7"` + a 4-byte big-endian payload
  length + payload bytes, then embedded MSB-first into the requested 1–8 LSBs
  of PCM samples.
- `resolve_header_start_sample(...)` and `resolve_payload_start_sample(...)`
  (Person 5's HMAC-based `derive_start_location(...)`, applied as a two-step
  locator) select the start sample for a small fixed-length header
  (`b"CSFAHD1"` + declared payload length) and then for the main payload
  frame, mirroring the image encoder's header/payload split.
- Optional AES-256-GCM payload confidentiality is available via
  `encode_audio_file(...)`'s `encrypt_payload` flag, using Person 5's
  `protect_signed_envelope(...)`.
- `AudioEncodeResult` provides non-secret display data: output path, LSB depth,
  framed payload size, carriers used, capacity, and derived start location.
- The Audio GUI provides WAV/FLAC details, live capacity feedback, session-key
  generation, and cover/stego playback controls.

## Person 4: Audio Decoder & Verification

This repository provides the WAV audio-decoder and verification API for
**FR8: Extraction and decoding**, **FR9: Hash verification**, and
**FR10: Verdict generation**.

### Public imports

The WAV decoder is exposed through `audio_decoder` and is independent of the
GUI toolkit:

```python
from audio_decoder import AudioDecodeResult, decode_audio_file
from workflows.audio_workflow import decode_audio
```

### Decoder and verification design

- `decode_audio_file(...)` accepts a stego WAV, `lsb_depth`, start-location
  secret, media ID, and signer public-key PEM.
  `workflows.audio_workflow.decode_audio(...)` additionally accepts FLAC
  stego files, transparently converting to WAV before calling this core logic.
- It derives the fixed locator-header position using the shared
  `resolve_header_start_sample(...)` protocol, recovers `b"CSFAHD1"` and the
  framed length, then derives and extracts the main `b"CSF7"` payload frame.
- The extracted envelope is automatically decrypted when it is AES-GCM
  protected, then passed to `parse_and_verify(...)`; only a successfully
  verified payload is used for the subsequent media check.
- The decoder masks the selected PCM-sample LSBs, recomputes the stable media
  bytes, and calls `media_hash_matches(...)` for FR9.
- `AudioDecodeResult` returns the FR10 `Verdict`, a verified
  `VerificationPayload` when authentic, and a safe public error otherwise.
- `tests/test_audio_decoder.py` covers short and large authentic payloads plus
  wrong-context and missing-payload cases.

## Person 5: Crypto & Payload Core

This repository currently provides the shared, stateless Python library for
the INF2005 steganography project. Image and audio modules can use it to create
the verification record for **FR3: Payload generation**, sign it for **FR4:
Digital signature**, optionally encrypt it before LSB embedding, derive a
protected start location for **FR7: Variable start location**, and map failures
to **FR10: Verdict generation** outcomes.

### Public imports

```python
from crypto_payload import (
    build_payload, sign_payload, parse_and_verify, sha256_hex,
    derive_start_location, encrypt_bytes, decrypt_bytes,
    protect_signed_envelope, open_signed_envelope,
    media_hash_matches, verdict_for_error,
)
```

Private keys are only for local assignment demonstration. In a real system,
private signing keys and start secrets must remain outside the repository; a
public key may be distributed for verification.

### Security design

- `VerificationPayload` contains `media_id`, UTC timestamp, SHA-256 media hash,
  256-bit random nonce, format version, and JSON-safe metadata.
- Canonical UTF-8 JSON is signed with Ed25519. The signed envelope can be
  verified only with its paired public key.
- The Image and Audio encoder checkboxes can wrap the signed envelope with
  AES-256-GCM. A domain-separated HMAC derives its 256-bit key from the shared
  secret, media ID and cover type; the decoder detects and opens it automatically.
- Locator positions are derived with HMAC-SHA-256 over the secret, Media ID,
  cover type, capacity and payload length, with protocol-domain separation.
  For images, the clicked payload channel is held in the secret-located header
  and checked against signed metadata; AES hides that metadata when enabled.
  Both sides need the same secret and context. In production, keep secrets in
  secure configuration rather than source code or a committed `.env` file.
- The library keeps no state and creates no key files. It uses safe JSON only;
  it never uses `pickle` or `eval`.

Ed25519 and SHA-256/HMAC-SHA-256 are current standard cryptography, but this
prototype is not post-quantum secure. See [EVALUATION.md](EVALUATION.md) and
[DEBUG.md](DEBUG.md) for acceptance criteria, limitations, recovery, and safe
logging rules.

## Person 6: GUI Integration, Test Matrix, Innovation

This repository provides the integration, assessment, and documentation work
for **FR11: Positive and negative cases**, **FR12: Evidence and
reproducibility**, and **FR13: Innovation**.

### GUI

The desktop app lives under `src/app` (entry point), `src/gui` (CustomTkinter
presentation layer), and `src/workflows` (orchestration — the only layer that
coordinates `crypto_payload` with the per-cover-object modules). Launch it
after the `pip install -e .` step above:

```powershell
python -m app
```

A top nav bar (`gui/navigation.py`) switches between full-page views
(`gui/pages/`) instead of a tabview: **Image**, **Audio**, **Video**, and
**Attack Sim**. Everything else
(overview, test cases, innovation, documentation) stays as real files
(`docs/`, `README.md`) rather than duplicated GUI pages.

The **Image** page shows Embed and Extract & Verify side by side. It supports
PNG selection, session Ed25519 key generation, selectable 1–8-bit LSB depth,
mouse-selected payload placement with secret-based recovery, live capacity checks, embedding, extraction, signature
verification, optional AES-GCM payload protection, media-hash verification, and verdict display. After embedding it
also renders an exact LSB-change map and a relative embedding-density heat
map. The first shows precisely which selected low bits changed; the second
counts changed pixels before grouping them into an easy-to-read overview, so
sparse one-bit changes do not disappear.

The **Audio** page mirrors this layout for WAV/FLAC workflows. Its encoder provides
audio information, capacity feedback, session-key generation, optional AES-GCM protection, embedding, and
cover/stego playback. After embedding, it also displays a selected-LSB change
map and an embedding-density timeline; its verification panel collects the
shared verification context and presents result fields consistently with the
image page.

The **Video** page embeds and extracts the same signed-payload scheme inside a
video's audio track, using `video_stego`/`video_decoder`; its media hash
covers both the video stream (via ffmpeg's `streamhash`) and the audio track
together, so tampering with either is detected. The **Attack Sim** page runs
one-click negative-case simulations (`attack_sim`) against an already-authentic
stego file, then feeds the result back through the same verification pipeline.

The supporting assessment material remains in real files rather than duplicate
GUI pages: `docs/TEST_MATRIX.md` defines test cases, `docs/INNOVATION.md`
documents the HMAC-derived start location, and `EVALUATION.md` defines the
shared crypto acceptance criteria.

### Reproducing submitted samples

The reproducible sample set is stored in `Sample Files/`; the exact Media IDs,
LSB depths, start-location secrets, public keys and expected verdicts are in
`P3-7 Key Instructions.txt`. Test screenshots and their expected results are
compiled in `P3-7 Test Evidence.pdf`.

```text
Sample Files/
├── image_orig.png
├── image_encrypted.png
├── image_tampered.png
├── image_toosmall.png
├── wav_orig.wav
├── wav_encrypted.wav
├── wav_fail_test_case.wav
├── flac_orig.flac
├── flac_encrypted.flac
├── Video_Cover.mp4
├── Video_Stego.mp4
├── Tampered_frame_edit.mp4
├── Tampered_audio_edit.mp4
├── Tampered_extra_track.mp4
├── reexported.mp4
├── without audio.mp4
└── public_key.txt
P3-7 Key Instructions.txt
P3-7 Test Evidence.pdf
```

`image_toosmall.png` and `wav_fail_test_case.wav` are small covers for capacity
failure tests. The `_encrypted` filenames are retained from the current
image/audio sample set, but their current payload metadata reports `Signed
only`; AES-256-GCM was not enabled when those particular samples were created.

To verify a sample in the GUI:

1. Open the matching Image, Audio, or Video page and select the protected file.
2. Enter the Media ID, LSB depth and demonstration secret from
   `P3-7 Key Instructions.txt`.
3. Paste the matching public key. The GUI accepts either the documented raw
   Base64 value or a complete PEM public key.
4. Run extraction and verification. The protected sample should be
   `Authentic`; `image_tampered.png` should produce `Tampered`.

The public key verifies the Ed25519 signature; it does not decrypt AES. The
AES key is derived from the shared demonstration secret and media context.
Private signing keys and derived AES keys must not be submitted. Any secret
included for sample reproducibility must be disposable and must never be
reused outside this assignment.

### Expected verdicts

| Verdict | Meaning |
| --- | --- |
| `Authentic` | Payload extraction, optional AES opening, signature verification and media-hash comparison succeeded. |
| `Tampered` | The signed payload is valid, but the current stable media hash does not match. |
| `Signature Invalid` | A payload was recovered, but the supplied public key could not verify its signature. |
| `Payload Missing` | No valid locator/payload was found using the supplied Media ID, LSB depth and secret. |
| `Wrong Start Location` | Start-location validation explicitly failed where the workflow can distinguish that condition. |
| `Cannot Verify` | Verification failed for another validation, key, decryption or format error. |


### P1--P4 integration outline

1. Hash the agreed **stable pre-embedding representation** (not an already
   changed stego file), then call `build_payload` and `sign_payload`.
2. For the confidential custom case, enable the encoder's AES-GCM checkbox.
   `protect_signed_envelope` derives a separate encryption key from the shared
   secret and context; `open_signed_envelope` handles plain and encrypted files.
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
