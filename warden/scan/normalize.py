"""Turn raw output of Bandit, Semgrep, Checkov and detect-secrets into Findings."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

from ..model import Finding

BANDIT_SEV = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
BANDIT_CATEGORY = {
    "B105": "hardcoded-secret", "B324": "weak-hash", "B501": "tls-verification-disabled",
    "B506": "unsafe-deserialization", "B608": "sql-injection", "B201": "debug-mode",
    "B113": "request-without-timeout",
}
SEMGREP_CATEGORY = {
    "careloop-sql-fstring": "sql-injection",
    "careloop-yaml-unsafe-load": "unsafe-deserialization",
    "careloop-missing-ownership-check": "broken-object-authorization",
    "careloop-admin-without-role-check": "missing-function-authorization",
}
# Checkov check ids grouped into the handful of risk themes a small security team acts on.
CHECKOV_CATEGORY = {
    "CKV_AWS_20": "public-s3", "CKV_AWS_57": "public-s3", "CKV2_AWS_6": "public-s3",
    "CKV_AWS_18": "s3-logging", "CKV_AWS_21": "s3-versioning", "CKV_AWS_145": "s3-encryption",
    "CKV_AWS_24": "open-ssh", "CKV_AWS_25": "open-rdp", "CKV_AWS_260": "open-http",
    "CKV_AWS_16": "rds-encryption", "CKV_AWS_17": "rds-public", "CKV_AWS_157": "rds-multiaz",
    "CKV_AWS_39": "eks-public-endpoint", "CKV_AWS_38": "eks-public-cidr", "CKV_AWS_37": "eks-logging",
    "CKV_AWS_58": "eks-secrets-encryption",
    "CKV_AWS_62": "iam-wildcard", "CKV_AWS_63": "iam-wildcard", "CKV_AWS_355": "iam-wildcard",
    "CKV_AWS_289": "iam-privilege-escalation", "CKV_AWS_286": "iam-privilege-escalation",
    "CKV_AWS_287": "iam-credentials-exposure", "CKV_AWS_288": "iam-data-exfiltration",
    "CKV_AWS_290": "iam-write-without-constraint", "CKV_AWS_60": "iam-wildcard-assume",
}


def secret_key(line: int) -> str:
    """Scanners disagree on rule names and hashes but agree on the line, so a secret is
    identified by where it sits in the file."""
    return f"secret@{line}"


def bandit(raw: dict) -> list[Finding]:
    out = []
    for r in raw.get("results", []):
        cat = BANDIT_CATEGORY.get(r["test_id"], r["test_id"].lower())
        out.append(Finding("bandit", r["test_id"], BANDIT_SEV.get(r["issue_severity"], "low"), r["issue_text"],
                           r["filename"], r["line_number"], f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else "",
                           cat, resource=secret_key(r["line_number"]) if cat == "hardcoded-secret" else cat))
    return out


def semgrep(raw: dict) -> list[Finding]:
    out = []
    for r in raw.get("results", []):
        rid = r["check_id"].split(".")[-1]
        cat = SEMGREP_CATEGORY.get(rid, rid)
        meta = r["extra"].get("metadata", {})
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(r["extra"]["severity"], "medium")
        out.append(Finding("semgrep", rid, sev, r["extra"]["message"], r["path"], r["start"]["line"],
                           meta.get("cwe", ""), cat, resource=cat))
    return out


def checkov(raw: dict) -> list[Finding]:
    out = []
    for r in raw.get("results", {}).get("failed_checks", []):
        cat = CHECKOV_CATEGORY.get(r["check_id"], r["check_id"].lower())
        sev = "high" if cat in {"public-s3", "open-ssh", "rds-public", "iam-wildcard", "eks-public-endpoint",
                                "rds-encryption", "iam-privilege-escalation", "iam-credentials-exposure"} else "medium"
        out.append(Finding("checkov", r["check_id"], sev, r["check_name"], r["file_path"].lstrip("/"),
                           (r.get("file_line_range") or [0])[0], "", cat, resource=r["resource"]))
    return out


def detect_secrets(raw: dict) -> list[Finding]:
    out = []
    for path, hits in raw.get("results", {}).items():
        for h in hits:
            out.append(Finding("detect-secrets", h["type"], "high", f"Possible secret: {h['type']}", path,
                               h["line_number"], "CWE-798", "hardcoded-secret", resource=secret_key(h["line_number"])))
    return out
