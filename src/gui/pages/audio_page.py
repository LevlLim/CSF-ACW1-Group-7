"""Audio page placeholder — mirrors image_page.py's shape once audio_encoder exists."""

from __future__ import annotations

import customtkinter as ctk

from .. import theme


class AudioPage(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")
        ctk.CTkLabel(
            self,
            text="Audio encode/decode isn't implemented yet. Will do.",
            font=ctk.CTkFont(size=13),
            text_color=theme.PENDING_COLOR,
            justify="left",
        ).pack(anchor="nw", padx=24, pady=24)
