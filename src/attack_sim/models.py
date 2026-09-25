from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from crypto_payload import Verdict


@dataclass(frozen=True, slots=True)
class AttackSimulationResult:
    attack_name: str
    verdict: Verdict
    output_path: Path | None
    details: str