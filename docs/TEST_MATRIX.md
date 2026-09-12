# Test Matrix

Tracks the assignment's mandatory demo cases: at least 2 positive and 3
negative cases overall, with at least one positive and one negative case for
each cover object (image and audio). Verdicts come from
`crypto_payload.Verdict` / `verdict_for_error`.

Status values: `Ready` (can be demoed today), `Blocked` (waiting on a module
that doesn't exist yet), `Planned` (case is defined but not run yet).

## Image cases

| ID | Type | Payload | What it does | Expected verdict | Status |
| --- | --- | --- | --- | --- | --- |
| IMG-P1 | Positive | Short (one Learning Outcome sentence) | Embed, then extract with the correct secret + public key | Authentic | Blocked — image decoder not implemented |
| IMG-P2 | Positive | Large (Project Overview paragraph) | Same as IMG-P1 with a bigger payload, at a higher LSB depth | Authentic | Blocked — image decoder not implemented |
| IMG-N1 | Negative | Custom (team-chosen) | Flip a pixel byte in the saved stego PNG after embedding, then extract | Tampered | Blocked — image decoder not implemented |
| IMG-N2 | Negative | Short | Extract using the wrong start-location secret | Wrong Start Location | Blocked — image decoder not implemented |
| IMG-N3 | Negative | Short | Extract using a public key that doesn't match the signer | Signature Invalid | Blocked — image decoder not implemented |
| IMG-N4 | Negative | Any | Attempt to embed a payload larger than the cover's capacity | Rejected before embedding (capacity check) | Ready — capacity check works today in the GUI |
| IMG-CAP | Capacity check | — | Compare payload size vs. cover size before embedding | Pass/fail shown in GUI | Ready |
| IMG-A2B | Party A→B | Custom | A embeds and "sends" (e.g. emails) the stego file; B downloads it independently and extracts + verifies | Authentic | Blocked — needs image decoder |

## Audio cases

| ID | Type | Payload | What it does | Expected verdict | Status |
| --- | --- | --- | --- | --- | --- |
| AUD-P1 | Positive | Short | Embed, then extract with the correct secret + public key | Authentic | Blocked — no audio_encoder yet |
| AUD-N1 | Negative | Short | Corrupt a sample in the stego WAV, then extract | Tampered | Blocked — no audio_encoder yet |
| AUD-N2 | Negative | Short | Extract with the wrong start-location secret | Wrong Start Location | Blocked — no audio_encoder yet |

## Notes

- Payload sizes per the spec: short = one Learning Outcome sentence, large =
  the Project Overview paragraph, custom = whatever the team defines to also
  demonstrate confidentiality (candidate: AES-256-GCM via
  `crypto_payload.encrypt_bytes` before embedding).
- Once the image decoder exists, re-run IMG-P1/P2 and IMG-N1..N3 for real and
  update Status to `Ready`, attaching screenshots/logs as evidence (FR12).
- `workflows.verification.verify_extracted_payload` already implements the
  authentic/tampered/signature-invalid outcomes used above — it just needs a
  real extractor in front of it (see `image_workflow.decode_image_stub`).
