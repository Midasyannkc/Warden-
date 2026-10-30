"""Data loss prevention for PHI leaving through an agent's tool calls."""
from __future__ import annotations

import re

PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "mrn": re.compile(r"\bMRN[:# ]*\d{6,10}\b", re.I),
    "dob": re.compile(r"\b(?:dob|date of birth)[:\s]*\d{4}-\d{2}-\d{2}\b", re.I),
    "phone": re.compile(r"\b\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
    "diagnosis": re.compile(r"\b(crohn|ibs-?d?|ulcerative colitis|calprotectin|biologic|diagnos[ie]s)\w*\b", re.I),
}


def scan(text: str) -> list[str]:
    return sorted(k for k, rx in PATTERNS.items() if rx.search(text or ""))


def redact(text: str) -> str:
    for k, rx in PATTERNS.items():
        text = rx.sub(f"[{k.upper()}]", text)
    return text
