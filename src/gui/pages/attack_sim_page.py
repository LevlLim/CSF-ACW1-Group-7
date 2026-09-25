"""Attack Sim page: one tab with a toggle to switch between the Image and
Audio attack simulation panels — only one is shown at a time."""

from __future__ import annotations

import customtkinter as ctk

from .. import theme
from ..panels.audio_attack_panel import AudioAttackPanel
from ..panels.image_attack_panel import ImageAttackPanel


class AttackSimPage(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Toggle row: choose which cover type's attacks to run.
        toggle_row = ctk.CTkFrame(self, fg_color="transparent")
        toggle_row.grid(row=0, column=0, sticky="w", pady=(0, 12))
        self.cover_type_toggle = ctk.CTkSegmentedButton(
            toggle_row, values=["Image", "Audio"], command=self.on_toggle
        )
        self.cover_type_toggle.set("Image")
        self.cover_type_toggle.pack(anchor="w")

        # Both panels are built once and swapped with tkraise — same pattern
        # main_window.py itself uses to switch top-level pages.
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)

        scroll_area = ctk.CTkScrollableFrame(content, fg_color="transparent")
        scroll_area.grid(row=0, column=0, sticky="nsew")
        scroll_area.grid_columnconfigure(0, weight=1)

        self.image_attack_panel = ImageAttackPanel(scroll_area)
        self.image_attack_panel.grid(row=0, column=0, sticky="new")

        self.audio_attack_panel = AudioAttackPanel(scroll_area)
        self.audio_attack_panel.grid(row=0, column=0, sticky="new")

        self.panels = {"Image": self.image_attack_panel, "Audio": self.audio_attack_panel}
        self.image_attack_panel.tkraise()

    def on_toggle(self, choice: str) -> None:
        self.panels[choice].tkraise()