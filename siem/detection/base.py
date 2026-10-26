"""Building blocks shared by every detection rule."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from ..db import SEVERITIES, SEVERITY_RANK

MAX_EVIDENCE_IDS = 100


def ts_str(epoch_seconds) -> str:
    """Epoch seconds -> 'YYYY-MM-DD HH:MM:SS' (UTC)."""
    return datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def escalate(severity: str, steps: int = 1) -> str:
    rank = min(SEVERITY_RANK.get(severity, 1) + steps, len(SEVERITIES) - 1)
    return SEVERITIES[rank]


def json_safe(value):
    """Round-trip through JSON so stored and freshly computed details compare equal."""
    return json.loads(json.dumps(value, default=lambda o: o.item() if hasattr(o, "item") else str(o)))


@dataclass
class Param:
    """Metadata for one configurable threshold (drives validation and the Rules page)."""
    name: str
    kind: str            # int | float | bool | str_list | int_list | pattern_map | choice | severity
    default: object
    label: str
    help: str = ""
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple = ()


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    first_seen: str
    last_seen: str
    event_count: int
    source_ip: str | None = None
    username: str | None = None
    event_ids: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    recommendation: str = ""

    @property
    def incident_key(self) -> str:
        return f"{self.rule_id}|{self.source_ip or '-'}|{self.username or '-'}|{self.first_seen}"

    def to_record(self) -> dict:
        return {
            "incident_key": self.incident_key,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "username": self.username,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": int(self.event_count),
            "event_ids": [int(i) for i in self.event_ids[:MAX_EVIDENCE_IDS]],
            "details": json_safe(self.details),
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "recommendation": self.recommendation,
        }


class Rule:
    """Base class. Subclasses set the metadata and implement ``detect``."""

    id: str = ""
    name: str = ""
    summary: str = ""            # one line for tables
    how_it_works: str = ""       # plain-English explanation shown on the Rules page
    false_positives: str = ""    # what commonly triggers it legitimately
    recommendation: str = ""     # analyst response
    mitre_tactic: str = ""
    mitre_technique: str = ""
    default_severity: str = "medium"
    params: tuple[Param, ...] = ()

    # Every rule also gets these two settings.
    COMMON = (
        Param("enabled", "bool", True, "Enabled"),
        Param("severity", "severity", None, "Base severity", choices=SEVERITIES),
    )

    def all_params(self) -> tuple[Param, ...]:
        return self.COMMON + tuple(self.params)

    def defaults(self) -> dict:
        values = {p.name: p.default for p in self.all_params()}
        values["severity"] = self.default_severity
        return values

    def merge_gap_seconds(self, cfg: dict) -> int:
        """How close two incidents must be (seconds) to count as the same incident."""
        return int(cfg.get("window_seconds", 300))

    def detect(self, df: pd.DataFrame, cfg: dict) -> list[Alert]:  # pragma: no cover
        raise NotImplementedError

    def alert(self, cfg: dict, **kwargs) -> Alert:
        kwargs.setdefault("severity", cfg.get("severity", self.default_severity))
        return Alert(
            rule_id=self.id,
            rule_name=self.name,
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
            recommendation=self.recommendation,
            **kwargs,
        )


def ids_of(frame: pd.DataFrame) -> list[int]:
    return [int(i) for i in frame["id"].to_numpy()[:MAX_EVIDENCE_IDS]]


def top_counts(series: pd.Series, n: int = 10) -> dict:
    counts = series.dropna().astype(str).value_counts().head(n)
    return {str(k): int(v) for k, v in counts.items()}


def epoch_seconds(series: pd.Series) -> np.ndarray:
    """datetime64 Series (any resolution) -> int64 epoch seconds."""
    return series.to_numpy().astype("datetime64[s]").astype(np.int64)
