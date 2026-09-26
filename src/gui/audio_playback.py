"""WAV playback for the audio GUI panels.

Uses sounddevice (bundles PortAudio, no compiler needed, wheels for
Windows/Mac/Linux) so cover-vs-stego comparison works from the GUI per the
spec's "GUI able to play... cover and stego objects for comparison"
requirement.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import sounddevice as sd

from audio_stego.common import AudioStegoError
from workflows.audio_workflow import read_audio

_DTYPE_BY_SAMPLE_WIDTH = {1: np.uint8, 2: np.int16}


def play_wav(path: str | Path) -> None:
    """Start playing a WAV or FLAC file. Returns immediately; playback runs in the
    background so it never blocks the GUI's event loop.
    """
    wav = read_audio(Path(path))
    dtype = _DTYPE_BY_SAMPLE_WIDTH.get(wav.sample_width)
    if dtype is None:
        raise AudioStegoError(f"Unsupported sample width for playback: {wav.sample_width}")
    samples = np.array(wav.samples, dtype=dtype).reshape(-1, wav.channels)
    sd.stop()
    sd.play(samples, samplerate=wav.frame_rate)


def stop_playback() -> None:
    sd.stop()
