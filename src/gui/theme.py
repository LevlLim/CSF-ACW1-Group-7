"""Shared colors, fonts, and layout helpers for the dark card-based look."""

from __future__ import annotations

import customtkinter as ctk

TEAM_TAG = "LAB-P3-7"

# Plain hex, not light/dark tuples — the app is locked to dark mode.
BACKGROUND_COLOR = "#0b0b0d"
CARD_FILL_COLOR = "#161618"
CARD_BORDER_COLOR = "#28282c"

CARD_CORNER_RADIUS = 8
_EYEBROW_COLOR = ("gray40", "gray60")
ERROR_COLOR = "#e5484d"
PENDING_COLOR = "#f5a623"
SUCCESS_COLOR = "#3fb950"
NORMAL_TEXT_COLOR = ("gray10", "gray90")

# Light-on-dark so the one primary action per panel (Embed & Sign / Extract
# & Verify) stands out from the regular accent-colored buttons.
CTA_FILL_COLOR = "#f2f2f2"
CTA_HOVER_COLOR = "#dcdcdc"
CTA_TEXT_COLOR = "#0b0b0d"

# Bold display font for headings; monospace for tags, labels, and numbers.
_HEADING_FAMILY = "Segoe UI"
_MONO_FAMILY = "Consolas"


def heading_font(size: int = 20) -> ctk.CTkFont:
    return ctk.CTkFont(family=_HEADING_FAMILY, size=size, weight="bold")


def mono_font(size: int = 12, weight: str = "normal") -> ctk.CTkFont:
    return ctk.CTkFont(family=_MONO_FAMILY, size=size, weight=weight)


def card(master: ctk.CTkBaseClass, title: str) -> ctk.CTkFrame:
    """A rounded section frame with a small uppercase title at the top."""
    frame = ctk.CTkFrame(
        master,
        corner_radius=CARD_CORNER_RADIUS,
        fg_color=CARD_FILL_COLOR,
        border_width=1,
        border_color=CARD_BORDER_COLOR,
    )
    eyebrow = ctk.CTkLabel(
        frame,
        text=title.upper(),
        font=mono_font(11, weight="bold"),
        text_color=_EYEBROW_COLOR,
        anchor="w",
    )
    eyebrow.grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(10, 2))
    frame.grid_columnconfigure(1, weight=1)
    return frame


def subheading(master: ctk.CTkBaseClass, text: str) -> ctk.CTkLabel:
    """A small bold label for a sub-section — no bordered card, cheaper to draw."""
    return ctk.CTkLabel(master, text=text.upper(), font=mono_font(10, weight="bold"), text_color=_EYEBROW_COLOR, anchor="w")


def panel_header(master: ctk.CTkBaseClass, number: int, title: str, subtitle: str = "") -> ctk.CTkFrame:
    """A plain numbered heading above a column, e.g. '1  Embed & Protect'."""
    frame = ctk.CTkFrame(master, fg_color="transparent")
    ctk.CTkLabel(frame, text=f"{number}  {title}", font=heading_font(16), anchor="w").pack(anchor="w")
    if subtitle:
        ctk.CTkLabel(
            frame, text=subtitle, font=ctk.CTkFont(size=12), text_color=_EYEBROW_COLOR, anchor="w"
        ).pack(anchor="w", pady=(2, 0))
    return frame


def stat_row(master: ctk.CTkBaseClass, captions: list[str]) -> tuple[ctk.CTkFrame, list[ctk.CTkLabel]]:
    """A bordered row of equal-width label/value stats, e.g. a capacity check.

    Returns the frame plus the value labels (same order as `captions`) so
    the caller can update them later.
    """
    frame = ctk.CTkFrame(
        master, corner_radius=CARD_CORNER_RADIUS, fg_color=CARD_FILL_COLOR, border_width=1, border_color=CARD_BORDER_COLOR
    )
    value_labels: list[ctk.CTkLabel] = []
    for i, caption in enumerate(captions):
        frame.grid_columnconfigure(i, weight=1)
        column = ctk.CTkFrame(frame, fg_color="transparent")
        column.grid(row=0, column=i, sticky="nsew", padx=12, pady=10)
        ctk.CTkLabel(
            column, text=caption.upper(), font=mono_font(10, weight="bold"), text_color=_EYEBROW_COLOR, anchor="w"
        ).pack(anchor="w")
        value_label = ctk.CTkLabel(column, text="–", font=mono_font(14), anchor="w")
        value_label.pack(anchor="w", pady=(2, 0))
        value_labels.append(value_label)
    return frame, value_labels


def kv_rows(master: ctk.CTkBaseClass, title: str, keys: list[str]) -> tuple[ctk.CTkFrame, dict[str, ctk.CTkLabel]]:
    """A card of label/value rows, e.g. a results panel.

    Returns the card plus a dict of key -> value label for later updates.
    """
    section = card(master, title)
    value_labels: dict[str, ctk.CTkLabel] = {}
    for i, key in enumerate(keys, start=1):
        ctk.CTkLabel(section, text=key, anchor="w").grid(row=i, column=0, sticky="w", padx=12, pady=4)
        value_label = ctk.CTkLabel(section, text="–", anchor="e", font=mono_font(12))
        value_label.grid(row=i, column=1, columnspan=2, sticky="e", padx=12, pady=4)
        value_labels[key] = value_label
    # Bottom padding under the last row, matching card()'s own top padding.
    ctk.CTkLabel(section, text="").grid(row=len(keys) + 1, column=0, pady=(0, 4))
    return section, value_labels
