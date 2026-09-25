"""Embed & Protect panel: hashes the cover WAV, signs a payload, checks
capacity, and embeds it into the audio using LSB replacement. Mirrors
embed_panel.py for images, including the message/note field and cover/stego
playback for comparison.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from audio_stego.common import AudioStegoError, load_wav_pcm
from crypto_payload import CryptoPayloadError, generate_ed25519_keypair
from workflows import audio_workflow

from .. import theme
from ..audio_playback import play_wav, stop_playback
from ..components import labeled_file_picker

_EXPECTED_FAILURES = (CryptoPayloadError, AudioStegoError, ValueError, OSError)
_PLAYBACK_FAILURES = (AudioStegoError, OSError, RuntimeError)


class AudioEmbedPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Build a signed payload and embed it into a cover WAV."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(
            master,
            fg_color=theme.BACKGROUND_COLOR,
            corner_radius=theme.CARD_CORNER_RADIUS,
            border_width=1,
            border_color=theme.CARD_BORDER_COLOR,
        )

        self.private_key_pem: bytes | None = None
        self.public_key_pem: bytes | None = None
        self.cover_path: Path | None = None
        self.stego_path: Path | None = None

        self.grid_columnconfigure(0, weight=1)

        # Everything is placed inside `content`, not `self` directly, so it
        # doesn't sit flush against the panel's own border.
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        content.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(content, 1, "Audio Encoder", "Hide verification data inside a WAV file").grid(
            row=row, column=0, sticky="w", pady=(0, 10)
        )
        row += 1

        labeled_file_picker(
            content, row, "Cover Audio", "Cover WAV", filetypes=[("WAV audio", "*.wav")], on_selected=self.on_cover_selected
        )
        row += 2

        theme.subheading(content, "Cover Info").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        info_frame, info_values = theme.stat_row(content, ["Channels", "Sample Rate", "Duration"])
        info_frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        self.channels_value, self.sample_rate_value, self.duration_value = info_values
        row += 1

        playback_row = ctk.CTkFrame(content, fg_color="transparent")
        playback_row.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        playback_row.grid_columnconfigure((0, 1, 2), weight=1)
        self.play_cover_button = ctk.CTkButton(
            playback_row, text="Play Cover", state="disabled", command=self.on_play_cover
        )
        self.play_cover_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.play_stego_button = ctk.CTkButton(
            playback_row, text="Play Stego", state="disabled", command=self.on_play_stego
        )
        self.play_stego_button.grid(row=0, column=1, sticky="ew", padx=4)
        ctk.CTkButton(playback_row, text="Stop", command=self.on_stop_playback).grid(
            row=0, column=2, sticky="ew", padx=(4, 0)
        )
        row += 1

        theme.subheading(content, "Payload & Settings").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        settings = ctk.CTkFrame(content, fg_color="transparent")
        settings.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        settings.grid_columnconfigure(1, weight=1)
        self.build_payload_settings(settings)
        row += 1

        theme.subheading(content, "Capacity Check").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        capacity_frame, capacity_values = theme.stat_row(content, ["Payload Size", "Available Capacity", "Status"])
        capacity_frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        self.payload_size_value, self.capacity_value, self.status_value = capacity_values
        row += 1

        self.encode_button = ctk.CTkButton(
            content,
            text="Embed & Sign",
            command=self.on_encode,
            fg_color=theme.CTA_FILL_COLOR,
            hover_color=theme.CTA_HOVER_COLOR,
            text_color=theme.CTA_TEXT_COLOR,
        )
        self.encode_button.grid(row=row, column=0, sticky="ew", pady=(0, 6))
        row += 1

        self.status_label = ctk.CTkLabel(content, text="", anchor="w", justify="left", wraplength=420)
        self.status_label.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.embed_result_card, self.embed_result_values = theme.kv_rows(
            content, "Embed Result", ["LSB depth", "Capacity", "Payload bytes", "Carriers used", "Start location"]
        )
        self.embed_result_card.grid(row=row, column=0, sticky="ew")

    def build_payload_settings(self, master: ctk.CTkFrame) -> None:
        ctk.CTkLabel(master, text="Media ID").grid(row=0, column=0, sticky="w", pady=6)
        self.media_id_entry = ctk.CTkEntry(master, font=theme.mono_font())
        self.media_id_entry.insert(0, self.default_media_id())
        self.media_id_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=6)

        ctk.CTkLabel(master, text="Message / note").grid(row=1, column=0, sticky="nw", pady=6)
        self.message_box = ctk.CTkTextbox(master, height=70)
        theme.style_textbox_selection(self.message_box)
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
        theme.style_textbox_selection(self.public_key_box)
        self.public_key_box.grid(row=6, column=0, columnspan=2, sticky="ew")
        self.public_key_box.configure(state="disabled")

    def default_media_id(self) -> str:
        return f"audio-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"

    def on_cover_selected(self, path: Path) -> None:
        self.cover_path = path
        try:
            wav = load_wav_pcm(path)
        except AudioStegoError as exc:
            self.set_status(f"Could not read WAV: {exc}", error=True)
            return
        self.channels_value.configure(text=str(wav.channels))
        self.sample_rate_value.configure(text=f"{wav.frame_rate} Hz")
        duration = wav.frame_count / wav.frame_rate if wav.frame_rate else 0
        self.duration_value.configure(text=f"{duration:.1f} s")
        self.play_cover_button.configure(state="normal")
        self.play_stego_button.configure(state="disabled")
        self.refresh_capacity()

    def on_play_cover(self) -> None:
        if self.cover_path is None:
            return
        try:
            play_wav(self.cover_path)
        except _PLAYBACK_FAILURES as exc:
            self.set_status(f"Could not play cover audio: {exc}", error=True)

    def on_play_stego(self) -> None:
        if self.stego_path is None:
            return
        try:
            play_wav(self.stego_path)
        except _PLAYBACK_FAILURES as exc:
            self.set_status(f"Could not play stego audio: {exc}", error=True)

    def on_stop_playback(self) -> None:
        stop_playback()

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
            self.status_value.configure(text="Awaiting Cover + Key", text_color=theme.PENDING_COLOR)
            return
        try:
            media_id = self.media_id_entry.get().strip()
            note = self.message_box.get("1.0", "end").strip()
            depth = int(self.lsb_depth_selector.get())
            status = audio_workflow.check_audio_capacity(self.cover_path, media_id, self.private_key_pem, depth, note=note)
        except _EXPECTED_FAILURES as exc:
            self.payload_size_value.configure(text="–")
            self.capacity_value.configure(text="–")
            self.status_value.configure(text="Error", text_color=theme.ERROR_COLOR)
            self.set_status(f"Capacity check failed: {exc}", error=True)
            return

        self.payload_size_value.configure(text=f"{status.needed_bytes} bytes")
        self.capacity_value.configure(text=f"{status.capacity_bytes} bytes")
        if status.fits:
            self.status_value.configure(text="Fits", text_color=theme.SUCCESS_COLOR)
        else:
            self.status_value.configure(text="Too large", text_color=theme.ERROR_COLOR)

    def on_encode(self) -> None:
        if self.cover_path is None:
            self.set_status("Select a cover WAV first.", error=True)
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
            status = audio_workflow.check_audio_capacity(self.cover_path, media_id, self.private_key_pem, depth, note=note)
            if not status.fits:
                self.set_status(
                    f"Payload does not fit: needs {status.needed_bytes} bytes, "
                    f"audio has {status.capacity_bytes} bytes at {depth}-bit LSB depth.",
                    error=True,
                )
                return

            stego_path = filedialog.asksaveasfilename(
                title="Save stego audio as", defaultextension=".wav", filetypes=[("WAV audio", "*.wav")]
            )
            if not stego_path:
                return

            result = audio_workflow.encode_audio(
                self.cover_path, stego_path, media_id, self.private_key_pem, secret, depth, note=note
            )
        except _EXPECTED_FAILURES as exc:
            self.set_status(f"Encoding failed: {exc}", error=True)
            return

        self.stego_path = Path(stego_path)
        self.play_stego_button.configure(state="normal")
        self.embed_result_values["LSB depth"].configure(text=str(result.lsb_depth))
        self.embed_result_values["Capacity"].configure(text=f"{result.capacity} samples")
        self.embed_result_values["Payload bytes"].configure(text=str(result.payload_bytes))
        self.embed_result_values["Carriers used"].configure(text=str(result.carriers_used))
        self.embed_result_values["Start location"].configure(text=str(result.start_location))
        self.set_status(f"Encoded successfully: {self.stego_path.name}")

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))
