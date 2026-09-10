Person 1 — Image Encoder
- FR1 (image input, PNG), FR5 (LSB embedding for image)
- Implement selectable LSB depth (1–8 bits) in GUI
- Implement chosen start-location embedding logic for image (FR7)
- Cover vs. stego image comparison view in GUI

Person 2 — Image Decoder & Verification
- FR8 (extraction from stego image), FR9 (hash recheck for image)
- Recover start location on the decode side, explain how it's found
- Build image positive + negative test cases (tampered pixel, wrong start location, missing payload)
- Verdict output for image cases (FR10)

Person 3 — Audio Encoder
- FR2 (audio input, WAV/PCM), FR6 (LSB embedding for audio)
- Selectable LSB depth (1–8 bits) for audio in GUI
- Chosen start-location embedding logic for audio (FR7)
- Cover vs. stego audio playback comparison in GUI

Person 4 — Audio Decoder & Verification
- FR8 (extraction from stego audio), FR9 (hash recheck for audio)
- Recover start location on decode side for audio, explain method
- Build audio positive + negative test cases (tampered sample, wrong start location, payload missing)
- Verdict output for audio cases (FR10)

Person 5 — Crypto & Payload Core (shared library used by both P1–P4)
- FR3: payload structure (media ID, timestamp, hash, nonce, metadata)
- FR4: key generation, digital signing, public-key verification
- Design + document how start-location secrecy is protected (e.g., derived from key/passphrase rather than stored in plaintext) — this directly answers the "start-location security" requirement (Criterion 1, 5 marks)
- Signature-invalid / tampered-payload handling logic feeding into FR10 verdicts

Person 6 — GUI Integration, Test Matrix, Innovation & Docs
- Wire all modules into one GUI (image + audio tabs, capacity check: payload size vs cover size)
- Build the full required test matrix: ≥2 positive + ≥3 negative cases, varying payload sizes (short = one LO, large = Project Overview paragraph, custom payload), party A→B send/extract demo scenario
- Own the Innovation writeup (FR13) — pick and justify one concrete enhancement (e.g., encrypted payload before embedding, randomized start-location derivation, checksum redundancy)