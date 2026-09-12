"""
Builds the required positive/negative image cases and confirms decoder.py
produces the correct verdict for each
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from PIL import Image

from crypto_payload import Verdict, build_payload, generate_ed25519_keypair, sha256_hex, sign_payload
from image_encoder import encode_image_file
from image_decoder import decode_image_file

LSB_DEPTH = 2
MEDIA_ID = "IMG001"
SECRET = b"team-shared-secret-2026"
WRONG_SECRET = b"an-incorrect-key"

GENERATED_FILES = ["cover.png", "stego_short.png", "stego_large.png", "stego_tampered.png"]

SHORT_MSG = "Explain how steganography can be used to embed hidden verification data."
LARGE_MSG = ("This undergraduate project requires student teams to design, implement and "
             "demonstrate a GUI-based LSB Replacement steganography program that protects "
             "and verifies both image and audio cover objects using steganography, hashing "
             "and digital signatures.")


def make_cover(path, size=(256, 256)):
    rng = np.random.default_rng(7)
    arr = rng.integers(0, 256, size=(size[1], size[0], 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, format="PNG")


def cover_media_hash(cover_path: str, lsb_depth: int) -> bytes:
    """Same masking convention decoder.py's _masked_media_bytes uses —
    mask out the low lsb_depth bits of every RGB channel before hashing,
    so the value is reproducible from the stego file alone later."""
    img = Image.open(cover_path).convert("RGB")
    arr = np.array(img)
    keep_mask = (0xFF << lsb_depth) & 0xFF
    masked = (arr.astype(np.uint8) & keep_mask).tobytes()
    return bytes.fromhex(sha256_hex(masked))


def build_and_encode(cover_path, stego_path, message, priv_pem, lsb_depth=LSB_DEPTH, secret=SECRET):
    media_hash = cover_media_hash(cover_path, lsb_depth)
    payload = build_payload(
        media_id=MEDIA_ID, media_hash=media_hash,
        metadata={"message": message}, timestamp=datetime.now(UTC),
    )
    envelope = sign_payload(payload, priv_pem)
    encode_image_file(
        cover_path, stego_path, envelope,
        lsb_depth=lsb_depth, start_secret=secret, media_id=MEDIA_ID,
    )


def run_case(name, stego_path, pub_pem, secret=SECRET, lsb_depth=LSB_DEPTH, media_id=MEDIA_ID):
    result = decode_image_file(
        stego_path, lsb_depth=lsb_depth, start_secret=secret,
        media_id=media_id, public_key_pem=pub_pem,
    )
    print(f"\n--- {name} ---")
    print(f"Verdict: {result.verdict}")
    if result.error:
        print(f"Error  : {type(result.error).__name__}: {result.error}")
    return result


def cleanup():
    """Delete the test PNGs this script generates, so repeated runs don't
    leave stray files lying around in the working directory."""
    for name in GENERATED_FILES:
        Path(name).unlink(missing_ok=True)


def main():
    priv_pem, pub_pem = generate_ed25519_keypair()
    make_cover("cover.png")

    try:
        # Case 1: positive, short message
        build_and_encode("cover.png", "stego_short.png", SHORT_MSG, priv_pem)
        r1 = run_case("Case 1: Positive (short message)", "stego_short.png", pub_pem)
        assert r1.verdict == Verdict.AUTHENTIC, r1.verdict

        # Case 2: positive, large message
        build_and_encode("cover.png", "stego_large.png", LARGE_MSG, priv_pem)
        r2 = run_case("Case 2: Positive (large message)", "stego_large.png", pub_pem)
        assert r2.verdict == Verdict.AUTHENTIC, r2.verdict

        # Case 3: negative, tamper a pixel's HIGH bits only (leave the low
        # lsb_depth bits untouched so the embedded payload itself still parses
        # and verifies — this isolates the FR9 media-hash check specifically)
        img = Image.open("stego_short.png")
        arr = np.array(img)
        high_bit_mask = (0xFF << LSB_DEPTH) & 0xFF
        arr[10, 10] = arr[10, 10] ^ high_bit_mask
        Image.fromarray(arr, "RGB").save("stego_tampered.png")
        r3 = run_case("Case 3: Negative (tampered after embedding)", "stego_tampered.png", pub_pem)
        assert r3.verdict in (Verdict.TAMPERED, Verdict.SIGNATURE_INVALID), r3.verdict

        # Case 4: negative, wrong secret at decode time
        r4 = run_case("Case 4: Negative (wrong start secret)", "stego_short.png", pub_pem, secret=WRONG_SECRET)
        assert r4.verdict in (Verdict.WRONG_START_LOCATION, Verdict.PAYLOAD_MISSING, Verdict.CANNOT_VERIFY), r4.verdict

        # Case 5: negative, no payload embedded at all
        r5 = run_case("Case 5: Negative (no payload embedded)", "cover.png", pub_pem)
        assert r5.verdict in (Verdict.PAYLOAD_MISSING, Verdict.WRONG_START_LOCATION, Verdict.CANNOT_VERIFY), r5.verdict

        print("\nAll cases produced expected verdicts.")
    finally:
        # Runs whether the test passed, failed, or errored — keeps the
        # working directory clean either way.
        cleanup()


if __name__ == "__main__":
    main()