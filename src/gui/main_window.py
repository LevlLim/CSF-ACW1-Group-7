"""Main window: header, nav bar, page container, status bar.

Layout only — each page owns its own content and logic.
"""

from __future__ import annotations

import customtkinter as ctk

from . import theme
from .navigation import NavigationBar
from .pages.audio_page import AudioPage
from .pages.image_page import ImagePage

APP_TITLE = "INF2005 Steganography Tool"
_TAGLINE = "STEGANOGRAPHY · VERIFY · PROTECT"

# (key, label) in display order. Test Cases / Innovation / Docs / Overview
# stay as real files instead of GUI pages — nav is just the working parts.
_PAGES = [("image", "Image"), ("audio", "Audio")]


class App(ctk.CTk):  # type: ignore[misc]  # customtkinter ships without type stubs
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_TITLE} — {theme.TEAM_TAG}")
        self.geometry("1400x900")
        self.minsize(1100, 700)
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=theme.BACKGROUND_COLOR)

        self.build_header()
        self.build_navigation()
        self.build_content()
        self.build_status_bar()

        self.nav_bar.set_active("image")

    def build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(16, 4))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text=theme.TEAM_TAG, font=theme.heading_font(18), anchor="w").grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkLabel(
            header, text=_TAGLINE, font=theme.mono_font(11, weight="bold"), text_color=("gray40", "gray60"), anchor="w"
        ).grid(row=0, column=1, sticky="w", padx=(16, 0))

    def build_navigation(self) -> None:
        nav_container = ctk.CTkFrame(self, fg_color="transparent")
        nav_container.pack(fill="x", padx=20, pady=(0, 4))
        self.nav_bar = NavigationBar(nav_container, _PAGES, on_select=self.show_page)
        self.nav_bar.pack(fill="x")

        # Plain 1px divider — cheaper than another bordered frame.
        ctk.CTkFrame(self, fg_color=theme.CARD_BORDER_COLOR, height=1, corner_radius=0).pack(fill="x", padx=20)

    def build_content(self) -> None:
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=16)
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        self.pages: dict[str, ctk.CTkFrame] = {
            "image": ImagePage(container),
            "audio": AudioPage(container),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def build_status_bar(self) -> None:
        status_bar = ctk.CTkFrame(self, fg_color="transparent")
        status_bar.pack(fill="x", padx=20, pady=(0, 12))
        status_bar.grid_columnconfigure(0, weight=1)

        self.ready_label = ctk.CTkLabel(
            status_bar, text="Ready.", font=ctk.CTkFont(size=11), text_color=("gray40", "gray60"), anchor="w"
        )
        self.ready_label.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            status_bar,
            text=f"INF2005 ACW1 2026  |  {theme.TEAM_TAG}",
            font=theme.mono_font(11),
            text_color=("gray40", "gray60"),
        ).grid(row=0, column=1, sticky="e")

    def show_page(self, key: str) -> None:
        self.pages[key].tkraise()
