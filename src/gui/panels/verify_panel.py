"""Extract & Verify panel: extracts a payload from a stego PNG and verifies it."""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from crypto_payload import CryptoPayloadError, Verdict
from image_decoder import ImageDecodeResult
from workflows import image_workflow

from .. import theme
from ..components import labeled_file_picker

_EXPECTED_FAILURES = (CryptoPayloadError, ValueError, OSError)


def _normalize_public_key_pem(text: str) -> bytes:
    """Accept either a full PEM block or just the base64 body.

    crypto_payload still needs full PEM (with the BEGIN/END lines) to parse
    the key, but pasting just the key without them is an easy mistake — wrap
    it back into PEM here instead of making the user get the format exact.
    """
    text = text.strip()
    if "BEGIN PUBLIC KEY" in text:
        return text.encode("ascii")
    return f"-----BEGIN PUBLIC KEY-----\n{text}\n-----END PUBLIC KEY-----\n".encode("ascii")


class VerifyPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Extract a payload from a stego PNG and verify it against a public key."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(
            master,
            fg_color=theme.BACKGROUND_COLOR,
            corner_radius=theme.CARD_CORNER_RADIUS,
            border_width=1,
            border_color=theme.CARD_BORDER_COLOR,
        )

        self.verify_stego_path: Path | None = None

        self.grid_columnconfigure(0, weight=1)

        # Everything is placed inside `content`, not `self` directly, so it
        # doesn't sit flush against the panel's own border.
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        content.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(content, 2, "Extract & Verify", "Recover the payload from a stego PNG").grid(
            row=row, column=0, sticky="w", pady=(0, 10)
        )
        row += 1

        labeled_file_picker(
            content, row, "Stego Image", "Stego PNG", filetypes=[("PNG image", "*.png")], on_selected=self.on_stego_selected
        )
        row += 2

        theme.subheading(content, "Verification Settings").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        settings = ctk.CTkFrame(content, fg_color="transparent")
        settings.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        settings.grid_columnconfigure(1, weight=1)
        self.build_settings(settings)
        row += 1

        self.verify_button = ctk.CTkButton(
            content,
            text="Extract & Verify",
            command=self.on_verify,
            fg_color=theme.CTA_FILL_COLOR,
            hover_color=theme.CTA_HOVER_COLOR,
            text_color=theme.CTA_TEXT_COLOR,
        )
        self.verify_button.grid(row=row, column=0, sticky="ew", pady=(0, 6))
        row += 1

        self.status_label = ctk.CTkLabel(content, text="", anchor="w", justify="left", wraplength=420)
        self.status_label.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.results_card, self.result_values = theme.kv_rows(
            content, "Results", ["Verdict", "Message", "Signature", "Hash match", "Start location", "Details"]
        )
        self.results_card.grid(row=row, column=0, sticky="ew")

    def build_settings(self, master: ctk.CTkFrame) -> None:
        ctk.CTkLabel(master, text="Media ID").grid(row=0, column=0, sticky="w", pady=6)
        self.media_id_entry = ctk.CTkEntry(master, font=theme.mono_font())
        self.media_id_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=6)

        ctk.CTkLabel(master, text="LSB depth (1-8)").grid(row=1, column=0, sticky="w", pady=6)
        self.lsb_depth_selector = ctk.CTkSegmentedButton(master, values=[str(i) for i in range(1, 9)])
        self.lsb_depth_selector.set("1")
        self.lsb_depth_selector.grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=6)

        ctk.CTkLabel(master, text="Start-location secret").grid(row=2, column=0, sticky="w", pady=6)
        self.secret_entry = ctk.CTkEntry(master, show="*")
        self.secret_entry.grid(row=2, column=1, sticky="ew", padx=(6, 0), pady=6)

        ctk.CTkLabel(master, text="Signer public key (PEM)").grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 2))
        self.public_key_box = ctk.CTkTextbox(master, height=70, font=theme.mono_font())
        self.public_key_box.grid(row=4, column=0, columnspan=2, sticky="ew")

    def on_stego_selected(self, path: Path) -> None:
        self.verify_stego_path = path

    def on_verify(self) -> None:
        if self.verify_stego_path is None:
            self.set_status("Select a stego PNG first.", error=True)
            return
        media_id = self.media_id_entry.get().strip()
        if not media_id:
            self.set_status("Enter the media ID used at encode time.", error=True)
            return
        secret = self.secret_entry.get().encode("utf-8")
        if not secret:
            self.set_status("Enter the start-location secret used at encode time.", error=True)
            return
        public_key_text = self.public_key_box.get("1.0", "end").strip()
        if not public_key_text:
            self.set_status("Paste the signer's public key.", error=True)
            return
        public_key_pem = _normalize_public_key_pem(public_key_text)
        depth = int(self.lsb_depth_selector.get())

        try:
            result = image_workflow.decode_image(self.verify_stego_path, depth, secret, media_id, public_key_pem)
        except _EXPECTED_FAILURES as exc:
            self.set_status(f"Verification failed: {exc}", error=True)
            return

        self.show_result(result)
        self.set_status(f"Verdict: {result.verdict}")

    def show_result(self, result: ImageDecodeResult) -> None:
        verdict = result.verdict
        payload = result.payload
        error = result.error

        self.result_values["Verdict"].configure(
            text=str(verdict), text_color=(theme.SUCCESS_COLOR if verdict == Verdict.AUTHENTIC else theme.ERROR_COLOR)
        )
        self.result_values["Message"].configure(text=(payload.metadata.get("note", "") or "(none)") if payload else "–")
        self.result_values["Signature"].configure(text="Valid" if payload is not None else "–")
        self.result_values["Hash match"].configure(
            text="Yes" if verdict == Verdict.AUTHENTIC else ("No" if verdict == Verdict.TAMPERED else "–")
        )
        self.result_values["Start location"].configure(text="Found" if payload is not None else "–")
        self.result_values["Details"].configure(text=str(error) if error else "OK")

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))
