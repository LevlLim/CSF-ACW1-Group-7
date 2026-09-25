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
| IMG-P1 | Positive | Short (one Learning Outcome sentence) | Embed, then extract with the correct secret + public key | Authentic | Ready — image decoder implemented |
| IMG-P2 | Positive | Large (Project Overview paragraph) | Same as IMG-P1 with a bigger payload, at a higher LSB depth | Authentic | Ready — image decoder implemented |
| IMG-N1 | Negative | Custom (team-chosen) | Flip a pixel byte in the saved stego PNG after embedding, then extract | Tampered | Ready — image decoder implemented |
| IMG-N2 | Negative | Short | Extract using the wrong start-location secret | Wrong Start Location | Ready — image decoder implemented |
| IMG-N3 | Negative | Short | Extract using a public key that doesn't match the signer | Signature Invalid | Ready — image decoder implemented |
| IMG-N4 | Negative | Any | Attempt to embed a payload larger than the cover's capacity | Rejected before embedding (capacity check) | Ready — capacity check works today in the GUI |
| IMG-CAP | Capacity check | — | Compare payload size vs. cover size before embedding | Pass/fail shown in GUI | Ready |
| IMG-A2B | Party A→B | Custom | A embeds and "sends" (e.g. emails) the stego file; B downloads it independently and extracts + verifies | Authentic | Ready — image encode/decode workflow implemented |

## Audio cases

| ID | Type | Payload | What it does | Expected verdict | Status |
| --- | --- | --- | --- | --- | --- |
| AUD-P1 | Positive | Short | Embed, then extract with the correct secret + public key | Authentic | Ready — audio decoder implemented |
| AUD-P2 | Positive | Large (Project Overview paragraph) | Same as AUD-P1 with a bigger payload, at a higher LSB depth | Authentic | Ready — audio decoder implemented |
| AUD-N1 | Negative | Short | Corrupt a sample in the stego WAV, then extract | Tampered | Ready — audio decoder implemented |
| AUD-N2 | Negative | Short | Extract with the wrong start-location secret | Payload Missing | Ready — audio decoder implemented |
| AUD-N3 | Negative | Any | Extract an unmodified cover WAV with no payload | Payload Missing | Ready — audio decoder implemented |

## Notes

- Payload sizes per the spec: short = one Learning Outcome sentence, large =
  the Project Overview paragraph, custom = whatever the team defines to also
  demonstrate confidentiality (candidate: AES-256-GCM via
  `crypto_payload.encrypt_bytes` before embedding).
- Capture screenshots/logs from the ready image and audio cases as FR12
  demonstration evidence.
