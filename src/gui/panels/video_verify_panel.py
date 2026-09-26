"""Extract a payload from a stego video and verify it against a public key.

Mirrors audio_verify_panel.py. Verification runs in the background.
"""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from crypto_payload import CryptoPayloadError, Verdict
from video_decoder import VideoDecodeResult
from video_stego import VideoStegoError
from workflows import video_workflow

from .. import theme
from ..background import run_in_background
from ..components import labeled_file_picker
from ..video_playback import open_in_default_player
from .audio_verify_panel import _normalize_public_key_pem  # same paste-friendly PEM handling as audio
from .video_embed_panel import _THUMBNAIL_SIZE, _VIDEO_FILETYPES, _clear_image, _show_image

_EXPECTED_FAILURES = (CryptoPayloadError, VideoStegoError, ValueError, OSError)


class VideoVerifyPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Extract a payload from a stego video and verify it against a public key."""

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

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        content.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(content, 2, "Video Decoder", "Recover and verify the payload from a stego video").grid(
            row=row, column=0, sticky="w", pady=(0, 10)
        )
        row += 1

        labeled_file_picker(
            content, row, "Stego Video", "Stego video", filetypes=_VIDEO_FILETYPES, on_selected=self.on_stego_selected
        )
        row += 2

        preview_row = ctk.CTkFrame(content, fg_color="transparent")
        preview_row.grid(row=row, column=0, sticky="w", pady=(0, 12))
        self.stego_thumbnail = ctk.CTkLabel(
            preview_row, text="(no video)", width=_THUMBNAIL_SIZE[0], height=_THUMBNAIL_SIZE[1],
            fg_color=theme.CARD_FILL_COLOR, corner_radius=theme.CARD_CORNER_RADIUS,
        )
        self.stego_thumbnail.grid(row=0, column=0, padx=(0, 12))
        self.open_stego_button = ctk.CTkButton(
            preview_row, text="Open Stego in Player", state="disabled", command=self.on_open_stego
        )
        self.open_stego_button.grid(row=0, column=1, sticky="w")
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

    def on_stego_selected(self, path: Path) -> bool:
        try:
            thumbnail = video_workflow.video_thumbnail(path)
        except _EXPECTED_FAILURES as exc:
            # Still allow verifying it: the verdict will explain what is wrong.
            self.verify_stego_path = path
            _clear_image(self.stego_thumbnail, "(no preview)")
            self.open_stego_button.configure(state="normal")
            self.set_status(f"No preview available ({exc}); you can still run verification.", error=True)
            return True
        self.verify_stego_path = path
        _show_image(self.stego_thumbnail, thumbnail, _THUMBNAIL_SIZE)
        self.open_stego_button.configure(state="normal")
        self.set_status(f"Stego video selected: {path.name}")
        return True

    def on_open_stego(self) -> None:
        if self.verify_stego_path is None:
            return
        try:
            open_in_default_player(self.verify_stego_path)
        except (OSError, RuntimeError) as exc:
            self.set_status(f"Could not open the video player: {exc}", error=True)

    def on_verify(self) -> None:
        if self.verify_stego_path is None:
            self.set_status("Select a stego video first.", error=True)
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
        stego_path = self.verify_stego_path

        def work() -> VideoDecodeResult:
            return video_workflow.decode_video(stego_path, depth, secret, media_id, public_key_pem)

        self.verify_button.configure(state="disabled", text="Verifying…")
        theme.set_verdict_banner(self.verdict_frame, self.verdict_label, "Verifying…", "pending")
        self.set_status("Extracting the audio track and checking signature + hashes…")
        run_in_background(self, work, self.on_verify_done, self.on_verify_failed)

    def on_verify_done(self, result: VideoDecodeResult) -> None:
        self.verify_button.configure(state="normal", text="Extract & Verify")
        self.show_result(result)
        self.set_status(f"Verdict: {result.verdict}")

    def on_verify_failed(self, error: Exception) -> None:
        self.verify_button.configure(state="normal", text="Extract & Verify")
        theme.set_verdict_banner(self.verdict_frame, self.verdict_label, f"✕  {Verdict.CANNOT_VERIFY}", "error")
        self.set_status(f"Verification failed: {error}", error=True)

    def show_result(self, result: VideoDecodeResult) -> None:
        verdict = result.verdict
        steps = result.explanation

        if verdict == Verdict.AUTHENTIC:
            theme.set_verdict_banner(self.verdict_frame, self.verdict_label, f"✓  {verdict}", "success")
        else:
            theme.set_verdict_banner(self.verdict_frame, self.verdict_label, f"✕  {verdict}", "error")

        payload = result.payload
        self.message_display.configure(text=(payload.metadata.get("note", "") or "(none)") if payload else "–")

        signature_ok = any(step.startswith("Signature verified") for step in steps)
        location_found = next((step for step in steps if step.startswith("Header found")), None)
        self.result_values["Signature"].configure(
            text="Valid" if signature_ok else ("Invalid" if verdict == Verdict.SIGNATURE_INVALID else "–")
        )
        self.result_values["Hash match"].configure(
            text="Yes" if verdict == Verdict.AUTHENTIC else ("No" if verdict == Verdict.TAMPERED else "–")
        )
        self.result_values["Start location"].configure(text="Found" if location_found else "Not found")
        self.result_values["Details"].configure(text=str(result.error) if result.error else "OK")

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))
