"""A slim top nav bar of plain buttons — cheaper and more flexible than CTkTabview."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from . import theme


class NavigationBar(ctk.CTkFrame):  # type: ignore[misc]  # customtkinter ships without type stubs
    def __init__(self, master: ctk.CTkBaseClass, pages: list[tuple[str, str]], on_select: Callable[[str], None]) -> None:
        """`pages` is a list of (key, label) pairs, in display order."""
        super().__init__(master, fg_color="transparent")
        self.on_select = on_select
        self.buttons: dict[str, ctk.CTkButton] = {}

        for i, (key, label) in enumerate(pages):
            button = ctk.CTkButton(
                self,
                text=label,
                fg_color="transparent",
                hover_color=theme.CARD_FILL_COLOR,
                text_color=theme.NORMAL_TEXT_COLOR,
                corner_radius=6,
                command=lambda key=key: self.select(key),
            )
            button.grid(row=0, column=i, padx=(0, 6), pady=8, sticky="w")
            self.buttons[key] = button

    def set_active(self, key: str) -> None:
        """Highlight `key`'s button and notify the callback."""
        self.select(key)

    def select(self, key: str) -> None:
        for button_key, button in self.buttons.items():
            button.configure(fg_color=theme.CARD_FILL_COLOR if button_key == key else "transparent")
        self.on_select(key)
