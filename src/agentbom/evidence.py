"""Evidence and finding types.

Findings reference observations instead of free-form claims so later reports can
trace security conclusions back to concrete evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Sequence

from .domain import Observation


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Evidence:
    observations: Sequence[Observation] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    entity_id: str
    evidence: Evidence = field(default_factory=Evidence)
    likelihood: float = 0.0
    confidence: float = 1.0
    remediation: str | None = None

    @property
    def normalized_score(self) -> float:
        severity_weight = {
            Severity.INFO: 0.0,
            Severity.LOW: 0.2,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.8,
            Severity.CRITICAL: 1.0,
        }[self.severity]
        return severity_weight * self.likelihood * self.confidence
