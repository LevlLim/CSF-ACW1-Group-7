"""Attack simulation panel (audio): runs the teammate's 4 audio_attacks
against a stego WAV and shows whether each attack was caught, using the
real audio_decoder.decode_audio_file verdict each attack function produces."""

from __future__ import annotations

import tempfile
from pathlib import Path

import customtkinter as ctk

from attack_sim import (
    simulate_audio_tampering,
    simulate_payload_corruption,
    simulate_wrong_key_verification,
    simulate_wrong_start_location,
)
from crypto_payload import CryptoPayloadError, Verdict

from .. import theme
from ..components import labeled_file_picker

_EXPECTED_FAILURES = (CryptoPayloadError, ValueError, OSError)

_ATTACKS = ["Tampering", "Wrong-Key Verification", "Payload Corruption", "Wrong Start-Location"]


def _normalize_public_key_pem(text: str) -> bytes:
    text = text.strip()
    if "BEGIN PUBLIC KEY" in text:
        return text.encode("ascii")
    return f"-----BEGIN PUBLIC KEY-----\n{text}\n-----END PUBLIC KEY-----\n".encode("ascii")


class AudioAttackPanel(ctk.CTkFrame): 
    """Run all 4 audio attack simulations against a genuine stego WAV."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(
            master,
            fg_color=theme.BACKGROUND_COLOR,
            corner_radius=theme.CARD_CORNER_RADIUS,
            border_width=1,
            border_color=theme.CARD_BORDER_COLOR,
        )

        self.stego_path: Path | None = None

        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        content.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(
            content, 2, "Audio Attack Simulation", "Run tampering, wrong-key, corruption, and wrong-location attacks"
        ).grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        labeled_file_picker(
            content, row, "Stego Audio", "Stego WAV", filetypes=[("WAV audio", "*.wav")], on_selected=self.on_stego_selected
        )
        row += 2

        theme.subheading(content, "Credentials Used At Encode Time").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        settings = ctk.CTkFrame(content, fg_color="transparent")
        settings.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        settings.grid_columnconfigure(1, weight=1)
        self.build_settings(settings)
        row += 1

        self.run_button = ctk.CTkButton(
            content,
            text="Run All Attacks",
            command=self.on_run,
            fg_color=theme.CTA_FILL_COLOR,
            hover_color=theme.CTA_HOVER_COLOR,
            text_color=theme.CTA_TEXT_COLOR,
        )
        self.run_button.grid(row=row, column=0, sticky="ew", pady=(0, 6))
        row += 1

        self.status_label = ctk.CTkLabel(content, text="", anchor="w", justify="left", wraplength=420)
        self.status_label.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.results_card, self.result_values = theme.kv_rows(content, "Attack Results", _ATTACKS)
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
        self.stego_path = path

    def on_run(self) -> None:
        if self.stego_path is None:
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

        output_dir = Path(tempfile.gettempdir()) / "attack_sim_outputs"

        try:
            tampering = simulate_audio_tampering(
                self.stego_path, output_dir / "audio_tampered.wav",
                lsb_depth=depth, start_secret=secret, media_id=media_id, public_key_pem=public_key_pem,
            )
            wrong_key = simulate_wrong_key_verification(
                self.stego_path, lsb_depth=depth, start_secret=secret, media_id=media_id,
            )
            corruption = simulate_payload_corruption(
                self.stego_path, output_dir / "audio_corrupted.wav",
                lsb_depth=depth, start_secret=secret, media_id=media_id, public_key_pem=public_key_pem,
            )
            wrong_location = simulate_wrong_start_location(
                self.stego_path, lsb_depth=depth, media_id=media_id, public_key_pem=public_key_pem,
            )
        except _EXPECTED_FAILURES as exc:
            self.set_status(f"Attack simulation failed: {exc}", error=True)
            return

        self.show_result("Tampering", tampering.verdict)
        self.show_result("Wrong-Key Verification", wrong_key.verdict)
        self.show_result("Payload Corruption", corruption.verdict)
        self.show_result("Wrong Start-Location", wrong_location.verdict)
        self.set_status("All 4 attacks run — see results below.")

    def show_result(self, key: str, verdict: Verdict) -> None:
        label = self.result_values[key]
        if verdict == Verdict.AUTHENTIC:
            label.configure(text=f"✕  NOT DETECTED ({verdict})", text_color=theme.ERROR_COLOR)
        else:
            label.configure(text=f"✓  Defended ({verdict})", text_color=theme.SUCCESS_COLOR)

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))