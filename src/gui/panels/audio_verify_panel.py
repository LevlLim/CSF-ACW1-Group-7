"""Extract & Verify panel for audio: UI shell ready for the audio decoder.

Mirrors gui/panels/verify_panel.py for images. No audio decoder exists yet
(see workflows/audio_workflow.py's decode_audio_stub) — the panel already
collects and passes the same arguments image_decoder.decode_image_file
expects (stego path, lsb depth, start secret, media id, public key), so
swapping decode_audio_stub for the real call is the only change needed
once Person 4 builds one.
"""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from crypto_payload import CryptoPayloadError
from workflows import audio_workflow

from .. import theme
from ..audio_playback import play_wav, stop_playback
from ..components import labeled_file_picker
from audio_stego.common import AudioStegoError

_EXPECTED_FAILURES = (CryptoPayloadError, ValueError, OSError)
_PLAYBACK_FAILURES = (AudioStegoError, OSError, RuntimeError)


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


class AudioVerifyPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Extract a payload from a stego WAV and verify it against a public key.

    Pending — no audio decoder exists yet, so on_verify always reports
    "not implemented" instead of a real verdict.
    """

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
        theme.panel_header(content, 2, "Audio Decoder", "Pending — no audio decoder yet").grid(
            row=row, column=0, sticky="w", pady=(0, 10)
        )
        row += 1

        labeled_file_picker(
            content, row, "Stego Audio", "Stego WAV", filetypes=[("WAV audio", "*.wav")], on_selected=self.on_stego_selected
        )
        row += 2

        playback_row = ctk.CTkFrame(content, fg_color="transparent")
        playback_row.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        playback_row.grid_columnconfigure((0, 1), weight=1)
        self.play_stego_button = ctk.CTkButton(
            playback_row, text="Play Stego", state="disabled", command=self.on_play_stego
        )
        self.play_stego_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(playback_row, text="Stop", command=self.on_stop_playback).grid(
            row=0, column=1, sticky="ew", padx=(4, 0)
        )
        row += 1

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

        self.verdict_frame, self.verdict_label = theme.verdict_banner(content)
        self.verdict_frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.message_card, self.message_display = theme.message_card(content)
        self.message_card.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.results_card, self.result_values = theme.kv_rows(
            content, "Results", ["Signature", "Hash match", "Start location", "Details"]
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
        theme.style_textbox_selection(self.public_key_box)
        self.public_key_box.grid(row=4, column=0, columnspan=2, sticky="ew")

    def on_stego_selected(self, path: Path) -> None:
        self.verify_stego_path = path
        self.play_stego_button.configure(state="normal")

    def on_play_stego(self) -> None:
        if self.verify_stego_path is None:
            return
        try:
            play_wav(self.verify_stego_path)
        except _PLAYBACK_FAILURES as exc:
            self.set_status(f"Could not play stego audio: {exc}", error=True)

    def on_stop_playback(self) -> None:
        stop_playback()

    def on_verify(self) -> None:
        if self.verify_stego_path is None:
            self.set_status("Select a stego WAV first.", error=True)
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
            # No audio decoder exists yet — this already passes the same
            # arguments image_workflow.decode_image does, so replacing
            # decode_audio_stub with a real decode_audio in audio_workflow.py
            # is the only change needed once one exists.
            audio_workflow.decode_audio_stub(self.verify_stego_path, depth, secret, media_id, public_key_pem)
        except NotImplementedError as exc:
            self.message_display.configure(text="–")
            for label in self.result_values.values():
                label.configure(text="–")
            self.result_values["Details"].configure(text=str(exc), text_color=theme.PENDING_COLOR)
            theme.set_verdict_banner(self.verdict_frame, self.verdict_label, "Not implemented yet", "pending")
            self.set_status("Audio extraction/verification is not implemented yet.")
            return
        except _EXPECTED_FAILURES as exc:
            self.set_status(f"Verification failed: {exc}", error=True)
            return

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))
