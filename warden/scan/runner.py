"""Run the real scanners as subprocesses and return normalized Findings."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

from . import normalize

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env={**os.environ, "BC_SKIP_MAPPING": "TRUE"})


def run_all(root: str = ROOT, target: str = "target") -> list:
    findings = []
    with tempfile.TemporaryDirectory() as td:
        p = _run(["bandit", "-r", f"{target}/app", "-f", "json", "-q"], root)
        findings += normalize.bandit(json.loads(p.stdout or "{}"))
        p = _run(["semgrep", "--config", "semgrep_rules", "--metrics=off", "--json", f"{target}/app"], root)
        findings += normalize.semgrep(json.loads(p.stdout or "{}"))
        p = _run(["checkov", "-d", f"{target}/infra", "--framework", "terraform", "-o", "json", "--quiet"], root)
        raw = json.loads(p.stdout or "{}")
        raw = raw[0] if isinstance(raw, list) else raw
        findings += normalize.checkov(raw)
        p = _run(["detect-secrets", "scan", target], root)
        findings += normalize.detect_secrets(json.loads(p.stdout or "{}"))
    return findings
