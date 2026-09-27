"""Attack Sim page: one tab with a toggle to switch between the Image,
Audio and Video attack simulation panels — only one is shown at a time."""

from __future__ import annotations

import customtkinter as ctk

from ..panels.audio_attack_panel import AudioAttackPanel
from ..panels.image_attack_panel import ImageAttackPanel
from ..panels.video_attack_panel import VideoAttackPanel


class AttackSimPage(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkBaseClass,
    ) -> None:

        super().__init__(
            master,
            fg_color="transparent",
        )

        self.grid_columnconfigure(
            0,
            weight=1,
        )

        self.grid_rowconfigure(
            1,
            weight=1,
        )

        # ---------------------------------
        # Image / Audio / Video selector
        # ---------------------------------

        toggle_row = ctk.CTkFrame(
            self,
            fg_color="transparent",
        )

        toggle_row.grid(
            row=0,
            column=0,
            sticky="w",
            pady=(0, 12),
        )

        self.cover_type_toggle = (
            ctk.CTkSegmentedButton(
                toggle_row,
                values=[
                    "Image",
                    "Audio",
                    "Video",
                ],
                command=self.on_toggle,
            )
        )

        self.cover_type_toggle.set(
            "Image"
        )

        self.cover_type_toggle.pack(
            anchor="w"
        )

        # ---------------------------------
        # Main content area
        # ---------------------------------

        content = ctk.CTkFrame(
            self,
            fg_color="transparent",
        )

        content.grid(
            row=1,
            column=0,
            sticky="nsew",
        )

        content.grid_columnconfigure(
            0,
            weight=1,
        )

        content.grid_rowconfigure(
            0,
            weight=1,
        )

        # Keep a reference because we need to reset its scroll position.
        self.scroll_area = (
            ctk.CTkScrollableFrame(
                content,
                fg_color="transparent",
            )
        )

        self.scroll_area.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        self.scroll_area.grid_columnconfigure(
            0,
            weight=1,
        )

        # ---------------------------------
        # Create the three attack panels
        # ---------------------------------

        self.image_attack_panel = (
            ImageAttackPanel(
                self.scroll_area
            )
        )

        self.audio_attack_panel = (
            AudioAttackPanel(
                self.scroll_area
            )
        )

        self.video_attack_panel = (
            VideoAttackPanel(
                self.scroll_area
            )
        )

        self.panels = {
            "Image":
                self.image_attack_panel,

            "Audio":
                self.audio_attack_panel,

            "Video":
                self.video_attack_panel,
        }

        # Only Image should be visible when the page first opens.
        self.image_attack_panel.grid(
            row=0,
            column=0,
            sticky="new",
        )

    def on_toggle(
        self,
        choice: str,
    ) -> None:
        """
        Show only the selected attack panel.
        """

        # Hide ALL panels first.
        for panel in self.panels.values():
            panel.grid_remove()

        # Show only the selected one.
        self.panels[choice].grid(
            row=0,
            column=0,
            sticky="new",
        )

        # Wait for Tk to recalculate the panel height before resetting scroll.
        self.after_idle(
            self._reset_scroll
        )

    def _reset_scroll(
        self,
    ) -> None:
        """
        Update the scroll region and return
        to the top after changing panels.
        """

        self.update_idletasks()

        canvas = (
            self.scroll_area._parent_canvas
        )

        canvas.configure(
            scrollregion=canvas.bbox("all")
        )

        canvas.yview_moveto(0)