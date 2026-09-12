"""Small reusable widgets shared across GUI panels."""

from __future__ import annotations

from pathlib import Path
from tkinter import filedialog
from typing import Callable

import customtkinter as ctk

from . import theme


def labeled_file_picker(
    master: ctk.CTkBaseClass,
    row: int,
    subheading_text: str,
    field_label: str,
    *,
    filetypes: list[tuple[str, str]],
    on_selected: Callable[[Path], None],
) -> ctk.CTkLabel:
    """A subheading label plus a file picker row underneath.

    Uses two grid rows (bump the caller's row counter by 2).
    """
    theme.subheading(master, subheading_text).grid(row=row, column=0, sticky="w", pady=(0, 4))
    picker_row = ctk.CTkFrame(master, fg_color="transparent")
    picker_row.grid(row=row + 1, column=0, sticky="ew", pady=(0, 12))
    picker_row.grid_columnconfigure(1, weight=1)
    return file_picker_row(picker_row, 0, field_label, filetypes=filetypes, on_selected=on_selected)


def file_picker_row(
    master: ctk.CTkBaseClass,
    row: int,
    label_text: str,
    *,
    filetypes: list[tuple[str, str]],
    on_selected: Callable[[Path], None],
) -> ctk.CTkLabel:
    """Label + selected-path text + Browse button, all on one grid row.

    Calls `on_selected(path)` once a file is picked.
    """
    ctk.CTkLabel(master, text=label_text).grid(row=row, column=0, sticky="w", padx=12, pady=6)
    path_label = ctk.CTkLabel(master, text="(none selected)", anchor="w")
    path_label.grid(row=row, column=1, sticky="ew", padx=6, pady=6)

    def browse() -> None:
        path = filedialog.askopenfilename(title=label_text, filetypes=filetypes)
        if not path:
            return
        selected = Path(path)
        path_label.configure(text=selected.name)
        on_selected(selected)

    ctk.CTkButton(master, text="Browse...", command=browse).grid(row=row, column=2, padx=12, pady=6)
    return path_label
