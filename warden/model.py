"""Shared finding model. Every scanner is normalized into this one shape."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    title: str
    file: str
    line: int = 0
    cwe: str = ""
    category: str = ""
    resource: str = ""
    kev: bool = False
    sla_days: int = 0
    fingerprint: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = fingerprint(self)

    def to_dict(self):
        return asdict(self)


def fingerprint(f: Finding) -> str:
    """Stable identity for a finding: the same weakness in the same place hashes the same
    across tools and across line moves. Line numbers are deliberately excluded."""
    key = "|".join([f.category or f.rule, f.file, f.resource])
    return hashlib.sha256(key.encode()).hexdigest()[:16]
