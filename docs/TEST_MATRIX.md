# Test Matrix

Tracks the assignment's mandatory demo cases: at least 2 positive and 3
negative cases overall, with at least one positive and one negative case for
each cover object (image and audio). Verdicts come from
`crypto_payload.Verdict` / `verdict_for_error`.

Status values: `Evidence captured` (included in `P3-7 Test Evidence.pdf`) and
`Ready` (implemented and available for further evidence capture).

## Image cases

| ID | Type | Payload | What it does | Expected verdict | Status |
| --- | --- | --- | --- | --- | --- |
| IMG-P1 | Positive | Short (one Learning Outcome sentence) | Embed, then extract with the correct secret + public key | Authentic | Evidence captured |
| IMG-P2 | Positive | Large (Project Overview paragraph) | Same as IMG-P1 with a bigger payload, at a higher LSB depth | Authentic | Evidence captured |
| IMG-N1 | Negative | Custom (team-chosen) | Flip a pixel byte in the saved stego PNG after embedding, then extract | Tampered | Ready — image decoder implemented |
| IMG-N2 | Negative | Short | Extract using the wrong start-location secret | Wrong Start Location | Ready — image decoder implemented |
| IMG-N3 | Negative | Short | Extract using a public key that doesn't match the signer | Signature Invalid | Ready — image decoder implemented |
| IMG-N4 | Negative | Any | Attempt to embed a payload larger than the cover's capacity | Rejected before embedding (capacity check) | Evidence captured |
| IMG-N5 | Negative | Short | Change only an RGBA image's alpha channel after embedding | Tampered | Ready — alpha is included in the stable media hash |
| IMG-CAP | Capacity check | — | Compare payload size vs. cover size before embedding | Pass/fail shown in GUI | Evidence captured |
| IMG-A2B | Party A→B | Custom | A embeds and "sends" (e.g. emails) the stego file; B downloads it independently and extracts + verifies | Authentic | Ready — image encode/decode workflow implemented |
| IMG-CUSTOM | Positive | Confidential custom message | Enable AES-256-GCM, embed, then extract with the shared context | Authentic; AES-256-GCM shown | Ready — encrypted workflow tested |

## Audio cases

| ID | Type | Payload | What it does | Expected verdict | Status |
| --- | --- | --- | --- | --- | --- |
| AUD-P1 | Positive | Short | Embed, then extract with the correct secret + public key | Authentic | Evidence captured |
| AUD-P2 | Positive | Large (Project Overview paragraph) | Same as AUD-P1 with a bigger payload, at a higher LSB depth | Authentic | Evidence captured |
| AUD-P3 | Positive | Custom | Embed into a FLAC cover and save a FLAC stego file | Authentic | Evidence captured |
| AUD-N1 | Negative | Large | Attempt to embed a payload larger than the cover's capacity | Rejected before embedding | Evidence captured |
| AUD-N2 | Negative | Short | Extract using a different valid public key | Signature Invalid | Evidence captured |
| AUD-N3 | Negative | Short | Extract with the wrong start-location secret | Payload Missing | Evidence captured |
| AUD-N4 | Negative | Any | Extract an unmodified cover WAV with no payload | Payload Missing | Evidence captured |
| AUD-CUSTOM | Positive | Confidential custom message | Enable AES-256-GCM, embed, then extract with the shared context | Authentic; AES-256-GCM shown | Evidence captured |

## Notes

- Payload sizes per the spec: short = one Learning Outcome sentence, large =
  the Project Overview paragraph, and custom = a team-defined confidential
  message protected with the Image/Audio AES-256-GCM checkbox.
- Submitted screenshots are compiled in `P3-7 Test Evidence.pdf`.

## Video cases (optional challenge)

| ID | Type | Test | Expected verdict | Status |
| --- | --- | --- | --- | --- |
| VID-P1 | Positive | Extract `Video_Stego.mp4` using the documented settings | Authentic | Evidence captured |
| VID-N1 | Negative | Extract the original `Video_Cover.mp4` | Payload Missing | Sample supplied |
| VID-N2 | Negative | Extract `Tampered_frame_edit.mp4` | Tampered | Evidence captured |
| VID-N3 | Negative | Extract `Tampered_audio_edit.mp4` | Tampered | Evidence captured |
| VID-N4 | Negative | Extract `Tampered_extra_track.mp4` | Tampered | Evidence captured |
| VID-N5 | Negative | Extract `reexported.mp4` after lossy re-export | Payload Missing | Evidence captured |
| VID-N6 | Validation | Select `without audio.mp4` as the encoder cover | Rejected: no audio track | Evidence captured |
