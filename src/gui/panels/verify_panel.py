"""Extract & Verify panel — pending, since no image decoder exists yet."""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from workflows import image_workflow

from .. import theme
from ..components import labeled_file_picker


class VerifyPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Extract a payload from a stego PNG and verify it (not implemented yet)."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.verify_stego_path: Path | None = None

        self.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(self, 2, "Extract & Verify", "Pending — not implemented yet").grid(
            row=row, column=0, sticky="w", pady=(0, 10)
        )
        row += 1

        labeled_file_picker(
            self, row, "Stego Image", "Stego PNG", filetypes=[("PNG image", "*.png")], on_selected=self.on_stego_selected
        )
        row += 2

        theme.subheading(self, "Verification Settings").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        settings = ctk.CTkFrame(self, fg_color="transparent")
        settings.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        settings.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(settings, text="Start-location secret").grid(row=0, column=0, sticky="w", pady=6)
        self.secret_entry = ctk.CTkEntry(settings, show="*")
        self.secret_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=6)
        ctk.CTkLabel(settings, text="Signer public key (PEM)").grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 2))
        self.public_key_box = ctk.CTkTextbox(settings, height=70, font=theme.mono_font())
        self.public_key_box.grid(row=2, column=0, columnspan=2, sticky="ew")
        row += 1

        self.verify_button = ctk.CTkButton(
            self,
            text="Extract & Verify",
            command=self.on_verify,
            fg_color=theme.CTA_FILL_COLOR,
            hover_color=theme.CTA_HOVER_COLOR,
            text_color=theme.CTA_TEXT_COLOR,
        )
        self.verify_button.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.results_card, self.result_values = theme.kv_rows(
            self, "Results", ["Message", "Signature", "Hash match", "Start location", "Details"]
        )
        self.results_card.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        row += 1

        ctk.CTkLabel(
            self,
            text="Image extraction and verification isn't implemented yet.",
            justify="left",
            text_color=theme.PENDING_COLOR,
        ).grid(row=row, column=0, sticky="w")

    def on_stego_selected(self, path: Path) -> None:
        self.verify_stego_path = path

    def on_verify(self) -> None:
        try:
            image_workflow.decode_image_stub()
        except NotImplementedError as exc:
            for label in self.result_values.values():
                label.configure(text="–")
            self.result_values["Details"].configure(text=str(exc), text_color=theme.PENDING_COLOR)
