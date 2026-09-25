"""Image page: shows the Embed and Extract & Verify panels side by side.

The two panels don't share any state, so each lives in its own file under
gui/panels/ — this page just arranges them in a scrollable two-column layout.
"""

from __future__ import annotations

import customtkinter as ctk

from ..panels.embed_panel import EmbedPanel
from ..panels.verify_panel import VerifyPanel


class ImagePage(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # One scroll area for both columns — a CTkScrollableFrame per column
        # makes each one claim its own full width instead of sharing the row.
        scroll_area = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll_area.grid(row=0, column=0, sticky="nsew")
        scroll_area.grid_columnconfigure((0, 1), weight=1)

        embed_panel = EmbedPanel(scroll_area)
        embed_panel.grid(row=0, column=0, sticky="new", padx=(0, 12))

        verify_panel = VerifyPanel(scroll_area)
        verify_panel.grid(row=0, column=1, sticky="new", padx=(12, 0))
