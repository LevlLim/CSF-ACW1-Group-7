"""Embed & Protect panel: hashes the cover, signs a payload, checks capacity,
and embeds it into a PNG. This is the fully-working half of the Image page.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk
from PIL import Image

from crypto_payload import CryptoPayloadError, generate_ed25519_keypair
from workflows import image_workflow

from .. import theme
from ..components import labeled_file_picker

_THUMBNAIL_SIZE = (140, 140)

# DEBUG.md says callers should only catch these, not raw crypto exceptions,
# so a real bug still shows up as a crash instead of a vague error message.
_EXPECTED_FAILURES = (CryptoPayloadError, ValueError, OSError)


class EmbedPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Build a signed payload and embed it into a cover PNG."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.private_key_pem: bytes | None = None
        self.public_key_pem: bytes | None = None
        self.cover_path: Path | None = None
        self.stego_path: Path | None = None

        self.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(self, 1, "Embed & Protect", "Hide verification data inside a PNG image").grid(
            row=row, column=0, sticky="w", pady=(0, 10)
        )
        row += 1

        labeled_file_picker(
            self, row, "Cover Image", "Cover PNG", filetypes=[("PNG image", "*.png")], on_selected=self.on_cover_selected
        )
        row += 2

        theme.subheading(self, "Payload & Settings").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        settings = ctk.CTkFrame(self, fg_color="transparent")
        settings.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        settings.grid_columnconfigure(1, weight=1)
        self.build_payload_settings(settings)
        row += 1

        theme.subheading(self, "Capacity Check").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        capacity_frame, capacity_values = theme.stat_row(self, ["Payload Size", "Available Capacity", "Status"])
        capacity_frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        self.payload_size_value, self.capacity_value, self.status_value = capacity_values
        row += 1

        self.encode_button = ctk.CTkButton(
            self,
            text="Embed & Sign",
            command=self.on_encode,
            fg_color=theme.CTA_FILL_COLOR,
            hover_color=theme.CTA_HOVER_COLOR,
            text_color=theme.CTA_TEXT_COLOR,
        )
        self.encode_button.grid(row=row, column=0, sticky="ew", pady=(0, 6))
        row += 1

        self.status_label = ctk.CTkLabel(self, text="", anchor="w", justify="left", wraplength=420)
        self.status_label.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.build_previews(self, row)
        row += 1

        self.embed_result_card, self.embed_result_values = theme.kv_rows(
            self, "Embed Result", ["LSB depth", "Capacity", "Embedded", "Changed pixels"]
        )
        self.embed_result_card.grid(row=row, column=0, sticky="ew")

    def build_payload_settings(self, master: ctk.CTkFrame) -> None:
        ctk.CTkLabel(master, text="Media ID").grid(row=0, column=0, sticky="w", pady=6)
        self.media_id_entry = ctk.CTkEntry(master, font=theme.mono_font())
        self.media_id_entry.insert(0, self.default_media_id())
        self.media_id_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=6)

        ctk.CTkLabel(master, text="Message / note").grid(row=1, column=0, sticky="nw", pady=6)
        self.message_box = ctk.CTkTextbox(master, height=70)
        self.message_box.grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=6)
        self.message_box.bind("<KeyRelease>", lambda _event: self.refresh_capacity())

        ctk.CTkLabel(master, text="LSB depth (1-8)").grid(row=2, column=0, sticky="w", pady=6)
        self.lsb_depth_selector = ctk.CTkSegmentedButton(
            master, values=[str(i) for i in range(1, 9)], command=lambda _value: self.refresh_capacity()
        )
        self.lsb_depth_selector.set("1")
        self.lsb_depth_selector.grid(row=2, column=1, sticky="ew", padx=(6, 0), pady=6)

        ctk.CTkLabel(master, text="Start-location secret").grid(row=3, column=0, sticky="w", pady=6)
        self.secret_entry = ctk.CTkEntry(master, show="*")
        self.secret_entry.grid(row=3, column=1, sticky="ew", padx=(6, 0), pady=6)

        ctk.CTkButton(master, text="Generate Signing Keypair", command=self.on_generate_keypair).grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(10, 6)
        )
        key_label_row = ctk.CTkFrame(master, fg_color="transparent")
        key_label_row.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(6, 2))
        key_label_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(key_label_row, text="Public key (share with verifier)", anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(key_label_row, text="Copy", width=56, command=self.on_copy_public_key).grid(row=0, column=1, sticky="e")

        self.public_key_box = ctk.CTkTextbox(master, height=70, font=theme.mono_font())
        self.public_key_box.grid(row=6, column=0, columnspan=2, sticky="ew")
        self.public_key_box.configure(state="disabled")

    def build_previews(self, master: ctk.CTkFrame, row: int) -> None:
        previews = ctk.CTkFrame(master, fg_color="transparent")
        previews.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        previews.grid_columnconfigure((0, 1), weight=1)

        cover_col = ctk.CTkFrame(previews, fg_color="transparent")
        cover_col.grid(row=0, column=0, sticky="n", padx=(0, 6))
        ctk.CTkLabel(cover_col, text="Cover").pack(pady=(0, 4))
        self.cover_preview = ctk.CTkLabel(cover_col, text="(no image)", width=_THUMBNAIL_SIZE[0], height=_THUMBNAIL_SIZE[1])
        self.cover_preview.pack()

        stego_col = ctk.CTkFrame(previews, fg_color="transparent")
        stego_col.grid(row=0, column=1, sticky="n", padx=(6, 0))
        ctk.CTkLabel(stego_col, text="Stego").pack(pady=(0, 4))
        self.stego_preview = ctk.CTkLabel(stego_col, text="(not yet encoded)", width=_THUMBNAIL_SIZE[0], height=_THUMBNAIL_SIZE[1])
        self.stego_preview.pack()

    def default_media_id(self) -> str:
        return f"img-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"

    def on_cover_selected(self, path: Path) -> None:
        self.cover_path = path
        self.show_preview(self.cover_preview, path)
        self.refresh_capacity()

    def on_generate_keypair(self) -> None:
        self.private_key_pem, self.public_key_pem = generate_ed25519_keypair()
        self.public_key_box.configure(state="normal")
        self.public_key_box.delete("1.0", "end")
        self.public_key_box.insert("1.0", self.public_key_pem.decode("ascii"))
        self.public_key_box.configure(state="disabled")
        self.set_status("Keypair generated for this session (private key kept in memory only).")
        self.refresh_capacity()

    def on_copy_public_key(self) -> None:
        if self.public_key_pem is None:
            self.set_status("Generate a keypair first.", error=True)
            return
        self.clipboard_clear()
        self.clipboard_append(self.public_key_pem.decode("ascii"))
        self.set_status("Public key copied to clipboard.")

    def refresh_capacity(self) -> None:
        if self.cover_path is None or self.private_key_pem is None:
            self.payload_size_value.configure(text="–")
            self.capacity_value.configure(text="–")
            self.status_value.configure(text="Select cover + key", text_color=theme.PENDING_COLOR)
            return
        try:
            media_id = self.media_id_entry.get().strip()
            note = self.message_box.get("1.0", "end").strip()
            depth = int(self.lsb_depth_selector.get())
            envelope = image_workflow.build_signed_envelope(self.cover_path, media_id, note, self.private_key_pem)
            status = image_workflow.check_image_capacity(self.cover_path, envelope, depth)
        except _EXPECTED_FAILURES as exc:
            self.payload_size_value.configure(text="–")
            self.capacity_value.configure(text="–")
            self.status_value.configure(text="Error", text_color=theme.ERROR_COLOR)
            self.set_status(f"Capacity check failed: {exc}", error=True)
            return

        self.payload_size_value.configure(text=f"{status.needed_bits} bits")
        self.capacity_value.configure(text=f"{status.capacity_bits} bits")
        if status.fits:
            self.status_value.configure(text="Fits", text_color=theme.SUCCESS_COLOR)
        else:
            self.status_value.configure(text="Too large", text_color=theme.ERROR_COLOR)

    def on_encode(self) -> None:
        if self.cover_path is None:
            self.set_status("Select a cover PNG first.", error=True)
            return
        if self.private_key_pem is None:
            self.set_status("Generate a signing keypair first.", error=True)
            return
        secret = self.secret_entry.get().encode("utf-8")
        if not secret:
            self.set_status("Enter a start-location secret.", error=True)
            return
        media_id = self.media_id_entry.get().strip()
        note = self.message_box.get("1.0", "end").strip()
        depth = int(self.lsb_depth_selector.get())

        try:
            envelope = image_workflow.build_signed_envelope(self.cover_path, media_id, note, self.private_key_pem)
            status = image_workflow.check_image_capacity(self.cover_path, envelope, depth)
            if not status.fits:
                self.set_status(
                    f"Payload does not fit: needs {status.needed_bits} bits, "
                    f"image has {status.capacity_bits} bits at {depth}-bit LSB depth.",
                    error=True,
                )
                return

            stego_path = filedialog.asksaveasfilename(
                title="Save stego image as", defaultextension=".png", filetypes=[("PNG image", "*.png")]
            )
            if not stego_path:
                return

            result = image_workflow.encode_image(self.cover_path, stego_path, envelope, depth, secret, media_id)
        except _EXPECTED_FAILURES as exc:
            self.set_status(f"Encoding failed: {exc}", error=True)
            return

        self.stego_path = Path(stego_path)
        self.show_preview(self.stego_preview, self.stego_path)
        self.embed_result_values["LSB depth"].configure(text=str(result.lsb_depth))
        self.embed_result_values["Capacity"].configure(text=f"{result.capacity_bits} bits")
        self.embed_result_values["Embedded"].configure(text=f"{result.embedded_bits} bits")
        self.embed_result_values["Changed pixels"].configure(text=str(result.changed_pixels))
        self.set_status(f"Encoded successfully: {self.stego_path.name}")

    def show_preview(self, label: ctk.CTkLabel, path: Path) -> None:
        with Image.open(path) as source:
            thumb = source.copy()
        thumb.thumbnail(_THUMBNAIL_SIZE)
        photo = ctk.CTkImage(light_image=thumb, dark_image=thumb, size=thumb.size)
        label.configure(image=photo, text="")
        label.image = photo  # keep a reference alive; CTkLabel does not retain one

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))
