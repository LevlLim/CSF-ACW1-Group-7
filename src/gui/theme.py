"""Shared colors, fonts, and layout helpers for the dark card-based look."""

from __future__ import annotations

import customtkinter as ctk

TEAM_TAG = "LAB-P3-7"

# Plain hex, not light/dark tuples — the app is locked to light mode, except
# the header bar (HEADER_* below), which stays dark regardless. Mirrors
# src/gui/assets/console_theme.json, which applies the light body palette to
# CTk's own default-styled widgets (buttons, entries, etc).
BACKGROUND_COLOR = "#F5F7FA"
CARD_FILL_COLOR = "#FFFFFF"
CARD_BORDER_COLOR = "#E2E8F0"

CARD_CORNER_RADIUS = 8
PRIMARY_COLOR = "#1683D8"
_EYEBROW_COLOR = "#64748B"
ERROR_COLOR = "#DC2626"
PENDING_COLOR = PRIMARY_COLOR
SUCCESS_COLOR = "#16A34A"
NORMAL_TEXT_COLOR = "#0F172A"

# Light background tints for the verdict banner — same hue family as the
# ERROR/SUCCESS/PENDING text colors above, just much lower saturation so text
# stays readable on top.
ERROR_TINT_COLOR = "#FEF2F2"
PENDING_TINT_COLOR = "#EFF6FF"
SUCCESS_TINT_COLOR = "#F0FDF4"

# The header bar (identity + nav tabs) stays dark regardless of the light
# body, per the team's brief — it's the one piece of "console" look kept.
HEADER_BACKGROUND_COLOR = "#0B1220"
HEADER_HOVER_COLOR = "#16233A"
HEADER_TEXT_COLOR = "#F1F5F9"
HEADER_SUBTEXT_COLOR = "#94A3B8"
HEADER_ACTIVE_TAB_COLOR = PRIMARY_COLOR

# Solid dark navy so the one primary action per panel (Image Encoder /
# Image Decoder) stands out from the regular blue accent buttons, and ties
# back to the header's color for brand cohesion.
CTA_FILL_COLOR = "#0B1220"
CTA_HOVER_COLOR = "#16233A"
CTA_TEXT_COLOR = "#FFFFFF"

# Bold display font for headings; monospace for tags, labels, and numbers.
_HEADING_FAMILY = "Segoe UI"
_MONO_FAMILY = "Consolas"


def heading_font(size: int = 20) -> ctk.CTkFont:
    return ctk.CTkFont(family=_HEADING_FAMILY, size=size, weight="bold")


def style_textbox_selection(textbox: ctk.CTkTextbox) -> None:
    """Recolor a CTkTextbox's text-selection highlight.

    CTkTextbox doesn't expose selectbackground/selectforeground in its own
    theme (only the raw tkinter.Text widget it wraps supports them), so
    without this, selecting text — or even pressing Ctrl+A on an empty box —
    shows Tk's system-default bright-blue highlight bar instead of something
    that matches the app's palette.
    """
    textbox._textbox.configure(selectbackground=PRIMARY_COLOR, selectforeground="#FFFFFF")


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


def verdict_banner(master: ctk.CTkBaseClass) -> tuple[ctk.CTkFrame, ctk.CTkLabel]:
    """A large, color-coded status banner for a verification result.

    Returns the frame and its message label; call `set_verdict_banner` to
    update both the text and the color coding after creating it. Starts in
    the neutral/pending state (no result yet).
    """
    frame = ctk.CTkFrame(master, corner_radius=CARD_CORNER_RADIUS, fg_color=PENDING_TINT_COLOR, border_width=1, border_color=CARD_BORDER_COLOR)
    label = ctk.CTkLabel(frame, text="Awaiting Verification", font=heading_font(18), text_color=PENDING_COLOR, anchor="center")
    label.pack(fill="x", padx=16, pady=18)
    return frame, label


def set_verdict_banner(frame: ctk.CTkFrame, label: ctk.CTkLabel, text: str, status: str) -> None:
    """Update a verdict banner. `status` is 'success', 'error', or 'pending'."""
    color, tint = {
        "success": (SUCCESS_COLOR, SUCCESS_TINT_COLOR),
        "error": (ERROR_COLOR, ERROR_TINT_COLOR),
        "pending": (PENDING_COLOR, PENDING_TINT_COLOR),
    }[status]
    frame.configure(fg_color=tint)
    label.configure(text=text, text_color=color)


def message_card(master: ctk.CTkBaseClass) -> tuple[ctk.CTkFrame, ctk.CTkLabel]:
    """A dedicated card for the decoded message.

    A single kv_rows line truncates or squeezes long text — the spec's own
    "large message" test case is a full paragraph — so the message gets its
    own wrapping, readable display instead of sharing a row with short
    one-word values like "Valid" or "Found".
    """
    frame = card(master, "Decoded Message")
    label = ctk.CTkLabel(frame, text="–", anchor="w", justify="left", wraplength=420, font=mono_font(13))
    label.grid(row=1, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 12))
    return frame, label


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
