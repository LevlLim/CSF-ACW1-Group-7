"""Run slow work (video encode/verify) without freezing the window.

Tkinter widgets may only be touched from the main thread, so the worker
thread never updates the GUI itself: the main thread polls for the result
with ``after()`` and then calls ``on_done`` / ``on_error``.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, TypeVar

T = TypeVar("T")

_POLL_MS = 100


def run_in_background(
    widget: Any,
    work: Callable[[], T],
    on_done: Callable[[T], None],
    on_error: Callable[[Exception], None],
) -> None:
    outcome: dict[str, Any] = {}

    def worker() -> None:
        try:
            outcome["result"] = work()
        except Exception as exc:  # handed to on_error on the main thread, never swallowed
            outcome["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    def poll() -> None:
        if thread.is_alive():
            widget.after(_POLL_MS, poll)
        elif "error" in outcome:
            on_error(outcome["error"])
        else:
            on_done(outcome["result"])

    widget.after(_POLL_MS, poll)
