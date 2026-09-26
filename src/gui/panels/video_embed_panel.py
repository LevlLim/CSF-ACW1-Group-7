"""Embed & Protect panel for video: signs a payload covering the video AND
audio streams, hides it in the audio track, and shows cover vs stego.
Mirrors audio_embed_panel.py; encoding runs in the background so the
window stays responsive.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk
from PIL import Image

from audio_stego.common import AudioStegoError
from audio_stego_visuals import AudioStegoVisuals
from crypto_payload import CryptoPayloadError, generate_ed25519_keypair
from video_stego import VideoEncodeResult, VideoStegoError
from workflows import video_workflow

from .. import theme
from ..background import run_in_background
from ..components import labeled_file_picker
from ..video_playback import open_in_default_player

_EXPECTED_FAILURES = (CryptoPayloadError, VideoStegoError, AudioStegoError, ValueError, OSError)
_VIDEO_FILETYPES = [("Video", "*.mp4 *.mov *.m4v *.mkv"), ("All files", "*.*")]
_THUMBNAIL_SIZE = (200, 120)
_DIAGNOSTIC_SIZE = (280, 120)


class VideoEmbedPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Build a signed payload and embed it into a cover video's audio track."""

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
        self.cover_info: video_workflow.VideoInfo | None = None
        self.stego_path: Path | None = None

        self.grid_columnconfigure(0, weight=1)

        # Everything is placed inside `content`, not `self` directly, so it
        # doesn't sit flush against the panel's own border.
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        content.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(
            content, 1, "Video Encoder", "Hide verification data in a video's audio track"
        ).grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        labeled_file_picker(
            content, row, "Cover Video", "Cover video", filetypes=_VIDEO_FILETYPES, on_selected=self.on_cover_selected
        )
        row += 2

        theme.subheading(content, "Cover Info").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        info_frame, info_values = theme.stat_row(content, ["Duration", "Audio", "Streams"])
        info_frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        self.duration_value, self.audio_value, self.streams_value = info_values
        row += 1

        self.build_comparison(content, row)
        row += 2

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

        self.build_diagnostics(content, row)
        row += 2

        self.embed_result_card, self.embed_result_values = theme.kv_rows(
            content,
            "Embed Result",
            ["LSB depth", "Capacity", "Payload bytes", "Samples used", "Header at", "Payload at", "Video hash"],
        )
        self.embed_result_card.grid(row=row, column=0, sticky="ew")

    # ----- layout helpers -------------------------------------------------

    def build_comparison(self, master: ctk.CTkFrame, row: int) -> None:
        """First-frame thumbnails of cover and stego, each with an Open button."""
        theme.subheading(master, "Cover vs Stego (first frame)").grid(row=row, column=0, sticky="w", pady=(0, 4))
        frame = ctk.CTkFrame(master, fg_color="transparent")
        frame.grid(row=row + 1, column=0, sticky="ew", pady=(0, 12))
        frame.grid_columnconfigure((0, 1), weight=1)

        self.cover_thumbnail, self.open_cover_button = self._thumbnail_slot(frame, 0, "Cover", self.on_open_cover)
        self.stego_thumbnail, self.open_stego_button = self._thumbnail_slot(frame, 1, "Stego", self.on_open_stego)

    def _thumbnail_slot(
        self, master: ctk.CTkFrame, column: int, title: str, command: object
    ) -> tuple[ctk.CTkLabel, ctk.CTkButton]:
        slot = ctk.CTkFrame(master, fg_color="transparent")
        slot.grid(row=0, column=column, sticky="n", padx=(0, 6) if column == 0 else (6, 0))
        ctk.CTkLabel(slot, text=title).pack(pady=(0, 4))
        image_label = ctk.CTkLabel(
            slot, text="(no video)", width=_THUMBNAIL_SIZE[0], height=_THUMBNAIL_SIZE[1],
            fg_color=theme.CARD_FILL_COLOR, corner_radius=theme.CARD_CORNER_RADIUS,
        )
        image_label.pack()
        button = ctk.CTkButton(slot, text=f"Open {title} in Player", state="disabled", command=command)
        button.pack(fill="x", pady=(6, 0))
        return image_label, button

    def build_payload_settings(self, master: ctk.CTkFrame) -> None:
        ctk.CTkLabel(master, text="Media ID").grid(row=0, column=0, sticky="w", pady=6)
        self.media_id_entry = ctk.CTkEntry(master, font=theme.mono_font())
        self.media_id_entry.insert(0, self.default_media_id())
        self.media_id_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=6)
        self.media_id_entry.bind("<KeyRelease>", lambda _event: self.refresh_capacity())

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

    def build_diagnostics(self, master: ctk.CTkFrame, row: int) -> None:
        """The team's WAV diagnostics, applied to the video's audio track."""
        theme.subheading(master, "Audio-Track Stego Diagnostics").grid(row=row, column=0, sticky="w", pady=(0, 4))
        frame = ctk.CTkFrame(master, fg_color="transparent")
        frame.grid(row=row + 1, column=0, sticky="ew", pady=(0, 12))
        frame.grid_columnconfigure((0, 1), weight=1)
        self.lsb_change_preview = self._diagnostic_slot(frame, 0, "LSB Change Map")
        self.density_preview = self._diagnostic_slot(frame, 1, "Embedding Density")

    def _diagnostic_slot(self, master: ctk.CTkFrame, column: int, title: str) -> ctk.CTkLabel:
        slot = ctk.CTkFrame(master, fg_color="transparent")
        slot.grid(row=0, column=column, sticky="n", padx=(0, 6) if column == 0 else (6, 0))
        ctk.CTkLabel(slot, text=title).pack(pady=(0, 4))
        label = ctk.CTkLabel(
            slot, text="(generated after embedding)", width=_DIAGNOSTIC_SIZE[0], height=_DIAGNOSTIC_SIZE[1], wraplength=240
        )
        label.pack()
        return label

    def default_media_id(self) -> str:
        return f"video-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"

    # ----- events -----------------------------------------------------------

    def on_cover_selected(self, path: Path) -> bool:
        try:
            info = video_workflow.inspect_video(path)
            thumbnail = video_workflow.video_thumbnail(path)
        except _EXPECTED_FAILURES as exc:
            self.cover_path = None
            self.cover_info = None
            self.open_cover_button.configure(state="disabled")
            _clear_image(self.cover_thumbnail, "(no video)")
            self.set_status(f"Cannot use this video: {exc}", error=True)
            self.refresh_capacity()
            return False

        self.cover_path = path
        self.cover_info = info
        self.stego_path = None
        # A fresh media ID for every new cover, same as the Image tab.
        self.media_id_entry.delete(0, "end")
        self.media_id_entry.insert(0, self.default_media_id())
        self.duration_value.configure(text=f"{info.duration_seconds:.1f} s")
        self.audio_value.configure(text=f"{info.sample_rate} Hz · {info.channels} ch")
        self.streams_value.configure(text=" + ".join(info.stream_kinds))
        _show_image(self.cover_thumbnail, thumbnail, _THUMBNAIL_SIZE)
        _clear_image(self.stego_thumbnail, "(encode first)")
        self.open_cover_button.configure(state="normal")
        self.open_stego_button.configure(state="disabled")
        _clear_image(self.lsb_change_preview, "(generated after embedding)")
        _clear_image(self.density_preview, "(generated after embedding)")

        note = ""
        if len(info.stream_kinds) > 2:
            note = " Extra tracks will be dropped: the stego video keeps one video + one audio stream."
        self.set_status(f"Cover video selected: {path.name}.{note}")
        self.refresh_capacity()
        return True

    def on_open_cover(self) -> None:
        self._open(self.cover_path)

    def on_open_stego(self) -> None:
        self._open(self.stego_path)

    def _open(self, path: Path | None) -> None:
        if path is None:
            return
        try:
            open_in_default_player(path)
        except (OSError, RuntimeError) as exc:
            self.set_status(f"Could not open the video player: {exc}", error=True)

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
        if self.cover_info is None or self.private_key_pem is None:
            self.payload_size_value.configure(text="–")
            self.capacity_value.configure(text="–")
            self.status_value.configure(text="Awaiting Cover + Key", text_color=theme.PENDING_COLOR)
            return
        try:
            status = video_workflow.check_video_capacity(
                self.cover_info,
                self.media_id_entry.get().strip(),
                self.private_key_pem,
                int(self.lsb_depth_selector.get()),
                note=self.message_box.get("1.0", "end").strip(),
            )
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
        if self.cover_path is None or self.cover_info is None:
            self.set_status("Select a cover video first.", error=True)
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
            status = video_workflow.check_video_capacity(self.cover_info, media_id, self.private_key_pem, depth, note=note)
        except _EXPECTED_FAILURES as exc:
            self.set_status(f"Encoding failed: {exc}", error=True)
            return
        if not status.fits:
            self.set_status(
                f"Payload does not fit: needs {status.needed_bytes} bytes, "
                f"audio has {status.capacity_bytes} bytes at {depth}-bit LSB depth.",
                error=True,
            )
            return

        stego_name = filedialog.asksaveasfilename(
            title="Save stego video as", defaultextension=".mp4", filetypes=[("MP4 video", "*.mp4")]
        )
        if not stego_name:
            return

        cover_path, stego_path, private_key_pem = self.cover_path, Path(stego_name), self.private_key_pem

        def work() -> tuple[VideoEncodeResult, Image.Image, AudioStegoVisuals | None]:
            result = video_workflow.encode_video(cover_path, stego_path, media_id, private_key_pem, secret, depth, note)
            thumbnail = video_workflow.video_thumbnail(stego_path)
            try:
                visuals: AudioStegoVisuals | None = video_workflow.build_video_visuals(cover_path, stego_path, depth)
            except _EXPECTED_FAILURES:
                visuals = None  # diagnostics are a bonus; never fail a good encode over them
            return result, thumbnail, visuals

        self.encode_button.configure(state="disabled", text="Encoding… (includes self-check)")
        self.set_status("Encoding: extracting audio, embedding, remuxing, then verifying the output…")
        run_in_background(self, work, self.on_encode_done, self.on_encode_failed)

    def on_encode_done(self, outcome: tuple[VideoEncodeResult, Image.Image, AudioStegoVisuals | None]) -> None:
        result, thumbnail, visuals = outcome
        self.encode_button.configure(state="normal", text="Embed & Sign")
        self.stego_path = result.output_path
        _show_image(self.stego_thumbnail, thumbnail, _THUMBNAIL_SIZE)
        self.open_stego_button.configure(state="normal")

        seconds_per_sample = 1 / (result.sample_rate * result.channels)
        values = self.embed_result_values
        values["LSB depth"].configure(text=str(result.lsb_depth))
        values["Capacity"].configure(text=f"{result.capacity_bytes} bytes")
        values["Payload bytes"].configure(text=str(result.payload_bytes))
        values["Samples used"].configure(text=str(result.carriers_used))
        values["Header at"].configure(
            text=f"sample {result.header_start_sample} ({result.header_start_sample * seconds_per_sample:.2f} s)"
        )
        values["Payload at"].configure(
            text=f"sample {result.payload_start_sample} ({result.payload_start_sample * seconds_per_sample:.2f} s)"
        )
        values["Video hash"].configure(text=f"{result.video_hash_hex[:16]}… (unchanged)")

        if visuals is not None:
            _show_image(self.lsb_change_preview, visuals.lsb_change_map, _DIAGNOSTIC_SIZE)
            _show_image(self.density_preview, visuals.density_timeline, _DIAGNOSTIC_SIZE)
            changed = f" — {visuals.changed_samples} audio samples changed"
        else:
            _clear_image(self.lsb_change_preview, "(diagnostic unavailable)")
            _clear_image(self.density_preview, "(diagnostic unavailable)")
            changed = ""
        self.set_status(f"Encoded and self-checked: {result.output_path.name}{changed}. Video stream untouched.")

    def on_encode_failed(self, error: Exception) -> None:
        self.encode_button.configure(state="normal", text="Embed & Sign")
        self.set_status(f"Encoding failed: {error}", error=True)

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))


def _show_image(label: ctk.CTkLabel, image: Image.Image, size: tuple[int, int]) -> None:
    preview = image.copy()
    preview.thumbnail(size)
    photo = ctk.CTkImage(light_image=preview, dark_image=preview, size=preview.size)
    label.configure(image=photo, text="")
    label.image = photo  # keep a reference, or Tk drops the image


def _clear_image(label: ctk.CTkLabel, placeholder: str) -> None:
    label.configure(image=None, text=placeholder)
    label.image = None
