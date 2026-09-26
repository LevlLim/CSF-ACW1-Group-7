"""Attack simulation panel (video): runs the 6 realistic video attacks against
a stego video and shows whether each was caught, using the real
video_decoder verdict. Mirrors audio_attack_panel.py.

The attacked copies are kept in a folder next to the stego video, so they
can be opened, re-verified by hand, and submitted as tampered sample files.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import customtkinter as ctk
from PIL import Image

from attack_sim import (
    AttackSimulationResult,
    simulate_video_audio_edit,
    simulate_video_extra_track,
    simulate_video_frame_edit,
    simulate_video_reexport,
    simulate_video_wrong_key,
    simulate_video_wrong_start_location,
)
from crypto_payload import Verdict
from video_stego import VideoStegoError
from workflows import video_workflow

from .. import theme
from ..background import run_in_background
from ..components import labeled_file_picker
from ..video_playback import open_in_default_player
from .audio_verify_panel import _normalize_public_key_pem  # same paste-friendly PEM handling as audio
from .video_embed_panel import _VIDEO_FILETYPES, _clear_image, _show_image

_CARD_THUMBNAIL_SIZE = (300, 185)
_GALLERY_COLUMNS = 3

# Evidence gallery: (title, what was done, attacked file name or None for the genuine stego).
# Attacked entries are in the same order as the first four attacks in _ATTACKS.
_GALLERY = [
    ("Genuine stego", "Untouched protected video", None),
    ("Frame edit", "Picture changed, original audio kept", "1_frame_edit.mp4"),
    ("Audio edit", "0.1 s of sound replaced", "2_audio_edit.mp4"),
    ("Extra audio track", "Fake narration track added", "3_extra_track.mp4"),
    ("Edit + re-export", "Trimmed 1 s and re-compressed", "4_reexported.mp4"),
]

# Row label -> what a real attacker would be doing.
_ATTACKS = [
    "Frame edit (deepfake-style)",
    "Audio edit (dubbed words)",
    "Extra audio track (fake narration)",
    "Edit + re-export (trim 1 s)",
    "Wrong-key verification (impersonator)",
    "Wrong start location (guessed secret)",
]


class VideoAttackPanel(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    """Run all 6 video attack simulations against a genuine stego video."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(
            master,
            fg_color=theme.BACKGROUND_COLOR,
            corner_radius=theme.CARD_CORNER_RADIUS,
            border_width=1,
            border_color=theme.CARD_BORDER_COLOR,
        )

        self.stego_path: Path | None = None
        self.output_dir: Path | None = None

        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        content.grid_columnconfigure(0, weight=1)

        row = 0
        theme.panel_header(
            content, 3, "Video Attack Simulation",
            "Deepfake-style frame edit, dubbed audio, fake track, re-export, impersonator, guessed secret",
        ).grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        labeled_file_picker(
            content, row, "Stego Video", "Stego video", filetypes=_VIDEO_FILETYPES, on_selected=self.on_stego_selected
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

        self.status_label = ctk.CTkLabel(content, text="", anchor="w", justify="left", wraplength=560)
        self.status_label.grid(row=row, column=0, sticky="ew", pady=(0, 6))
        row += 1

        self.open_folder_button = ctk.CTkButton(
            content, text="Open Attacked Videos Folder", state="disabled", command=self.on_open_folder
        )
        self.open_folder_button.grid(row=row, column=0, sticky="w", pady=(0, 12))
        row += 1

        self.results_card, self.result_values = theme.kv_rows(content, "Attack Results", _ATTACKS)
        self.results_card.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        row += 1

        self.build_comparison(content, row)

    def build_comparison(self, master: ctk.CTkFrame, row: int) -> None:
        """Evidence gallery: the genuine stego and every attacked copy, each playable."""
        theme.subheading(master, "Attack Evidence: Genuine vs. Tampered Copies").grid(
            row=row, column=0, sticky="w", pady=(0, 6)
        )
        gallery = ctk.CTkFrame(master, fg_color="transparent")
        gallery.grid(row=row + 1, column=0, sticky="w")

        self.gallery_cards: list[tuple[ctk.CTkLabel, ctk.CTkLabel, ctk.CTkButton]] = []
        for index, (title, description, file_name) in enumerate(_GALLERY):
            grid_row, grid_column = divmod(index, _GALLERY_COLUMNS)
            self.gallery_cards.append(self._gallery_card(gallery, grid_row, grid_column, title, description, file_name))

    def _gallery_card(
        self, master: ctk.CTkFrame, grid_row: int, grid_column: int, title: str, description: str, file_name: str | None
    ) -> tuple[ctk.CTkLabel, ctk.CTkLabel, ctk.CTkButton]:
        card = ctk.CTkFrame(
            master, fg_color=theme.CARD_FILL_COLOR, corner_radius=theme.CARD_CORNER_RADIUS,
            border_width=1, border_color=theme.CARD_BORDER_COLOR,
        )
        card.grid(row=grid_row, column=grid_column, sticky="n", padx=(0, 14), pady=(0, 14))

        ctk.CTkLabel(card, text=title, font=theme.heading_font(14), anchor="w").pack(fill="x", padx=12, pady=(10, 0))
        ctk.CTkLabel(
            card, text=description, font=ctk.CTkFont(size=12), text_color=theme._EYEBROW_COLOR, anchor="w"
        ).pack(fill="x", padx=12, pady=(0, 8))
        image = ctk.CTkLabel(
            card, text="(run the attacks)", width=_CARD_THUMBNAIL_SIZE[0], height=_CARD_THUMBNAIL_SIZE[1],
            fg_color=theme.BACKGROUND_COLOR, corner_radius=theme.CARD_CORNER_RADIUS,
        )
        image.pack(padx=12)
        verdict = ctk.CTkLabel(card, text="–", font=theme.mono_font(12, weight="bold"))
        verdict.pack(pady=(8, 0))

        def play() -> None:
            self._play(self.stego_path if file_name is None else self._attacked_path(file_name))

        play_button = ctk.CTkButton(card, text="▶ Play", state="disabled", command=play)
        play_button.pack(fill="x", padx=12, pady=(6, 12))
        return image, verdict, play_button

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

        stego = self.stego_path
        output_dir = stego.parent / f"{stego.stem}_attacks"
        creds = {"lsb_depth": depth, "start_secret": secret, "media_id": media_id}

        def work() -> tuple[list[AttackSimulationResult], Verdict, list[Image.Image | None]]:
            output_dir.mkdir(exist_ok=True)
            results = [
                simulate_video_frame_edit(stego, output_dir / "1_frame_edit.mp4", public_key_pem=public_key_pem, **creds),
                simulate_video_audio_edit(stego, output_dir / "2_audio_edit.mp4", public_key_pem=public_key_pem, **creds),
                simulate_video_extra_track(stego, output_dir / "3_extra_track.mp4", public_key_pem=public_key_pem, **creds),
                simulate_video_reexport(stego, output_dir / "4_reexported.mp4", public_key_pem=public_key_pem, **creds),
                simulate_video_wrong_key(stego, **creds),
                simulate_video_wrong_start_location(stego, public_key_pem=public_key_pem, **creds),
            ]
            # The genuine card's verdict is measured, not assumed: verify the untouched stego too.
            genuine = video_workflow.decode_video(stego, depth, secret, media_id, public_key_pem).verdict
            videos = [stego if name is None else output_dir / name for _, _, name in _GALLERY]
            return results, genuine, [_thumbnail_or_none(video) for video in videos]

        self.output_dir = output_dir
        self.run_button.configure(state="disabled", text="Running attacks…")
        self.set_status("Creating attacked copies and verifying each one…")
        run_in_background(self, work, self.on_run_done, self.on_run_failed)

    def on_run_done(self, outcome: tuple[list[AttackSimulationResult], Verdict, list[Image.Image | None]]) -> None:
        results, genuine_verdict, thumbnails = outcome
        self.run_button.configure(state="normal", text="Run All Attacks")
        for key, result in zip(_ATTACKS, results):
            self.show_result(key, result.verdict)
        verdicts = [genuine_verdict, *(result.verdict for result in results[: len(_GALLERY) - 1])]
        self.show_gallery(thumbnails, verdicts)
        defended = sum(result.verdict != Verdict.AUTHENTIC for result in results)
        self.set_status(f"{defended}/{len(results)} attacks defended. Attacked copies saved in: {self.output_dir}")
        self.open_folder_button.configure(state="normal")

    def show_gallery(self, thumbnails: list[Image.Image | None], verdicts: list[Verdict]) -> None:
        for index, ((image, verdict_label, play_button), thumbnail, verdict) in enumerate(
            zip(self.gallery_cards, thumbnails, verdicts)
        ):
            if thumbnail is None:
                _clear_image(image, "(preview unavailable)")
            else:
                _show_image(image, thumbnail, _CARD_THUMBNAIL_SIZE)

            if index == 0:
                # The genuine copy should verify as Authentic.
                ok = verdict == Verdict.AUTHENTIC
                text, color = (f"✓  {verdict}", theme.SUCCESS_COLOR) if ok else (f"!  {verdict}", theme.ERROR_COLOR)
            elif verdict == Verdict.AUTHENTIC:
                text, color = f"✕  {verdict} (NOT DETECTED)", theme.ERROR_COLOR
            else:
                text, color = f"✕  {verdict}", theme.ERROR_COLOR
            verdict_label.configure(text=text, text_color=color)
            play_button.configure(state="normal")

    def on_run_failed(self, error: Exception) -> None:
        self.run_button.configure(state="normal", text="Run All Attacks")
        self.set_status(f"Attack simulation failed: {error}", error=True)

    def _attacked_path(self, name: str) -> Path | None:
        return None if self.output_dir is None else self.output_dir / name

    def _play(self, path: Path | None) -> None:
        if path is None or not path.exists():
            self.set_status("That video isn't available — run the attacks first.", error=True)
            return
        try:
            open_in_default_player(path)
        except (OSError, RuntimeError) as exc:
            self.set_status(f"Could not open the video player: {exc}", error=True)

    def on_open_folder(self) -> None:
        if self.output_dir is None:
            return
        try:
            if sys.platform == "win32":
                os.startfile(self.output_dir)  # type: ignore[attr-defined]  # Windows-only API
        except OSError as exc:
            self.set_status(f"Could not open the folder: {exc}", error=True)

    def show_result(self, key: str, verdict: Verdict) -> None:
        label = self.result_values[key]
        if verdict == Verdict.AUTHENTIC:
            label.configure(text=f"✕  NOT DETECTED ({verdict})", text_color=theme.ERROR_COLOR)
        else:
            label.configure(text=f"✓  Defended ({verdict})", text_color=theme.SUCCESS_COLOR)

    def set_status(self, text: str, error: bool = False) -> None:
        self.status_label.configure(text=text, text_color=(theme.ERROR_COLOR if error else theme.NORMAL_TEXT_COLOR))


def _thumbnail_or_none(video: Path) -> Image.Image | None:
    """First frame for a gallery card; a missing preview must never fail the attack run."""
    try:
        return video_workflow.video_thumbnail(video)
    except (VideoStegoError, OSError, ValueError):
        return None
