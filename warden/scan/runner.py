"""Run the real scanners as subprocesses and return normalized Findings.

The raw JSON from each tool is cached under out/ keyed by a hash of the scanned files, so
tests and reports re-run the tools only when the target actually changed. Delete
out/raw_scan_cache.json (or run `make rescan`) to force a fresh run."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess

from . import normalize

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, "out", "raw_scan_cache.json")


def _run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env={**os.environ, "BC_SKIP_MAPPING": "TRUE"})


def tree_hash(root: str, target: str) -> str:
    h = hashlib.sha256()
    for base in (target, "semgrep_rules"):
        for dp, dn, fn in sorted(os.walk(os.path.join(root, base))):
            dn[:] = sorted(d for d in dn if d != "__pycache__")
            for f in sorted(fn):
                if f.endswith(".pyc"):
                    continue
                p = os.path.join(dp, f)
                h.update(os.path.relpath(p, root).encode())
                h.update(open(p, "rb").read())
    return h.hexdigest()


def raw_scan(root: str, target: str) -> dict:
    p = _run(["bandit", "-r", f"{target}/app", "-f", "json", "-q"], root)
    bandit = json.loads(p.stdout or "{}")
    p = _run(["semgrep", "--config", "semgrep_rules", "--metrics=off", "--json", f"{target}/app"], root)
    semgrep = json.loads(p.stdout or "{}")
    p = _run(["checkov", "-d", f"{target}/infra", "--framework", "terraform", "-o", "json", "--quiet"], root)
    checkov = json.loads(p.stdout or "{}")
    checkov = checkov[0] if isinstance(checkov, list) else checkov
    p = _run(["detect-secrets", "scan", target], root)
    secrets = json.loads(p.stdout or "{}")
    return {"bandit": bandit, "semgrep": semgrep, "checkov": checkov, "detect-secrets": secrets}


def run_all(root: str = ROOT, target: str = "target", use_cache: bool = True) -> list:
    key = tree_hash(root, target)
    raw = None
    cache = os.path.join(root, "out", "raw_scan_cache.json")
    if use_cache and os.path.exists(cache):
        c = json.load(open(cache))
        if c.get("key") == key:
            raw = c["raw"]
    if raw is None:
        raw = raw_scan(root, target)
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        json.dump({"key": key, "raw": raw}, open(cache, "w"))
    findings = []
    findings += normalize.bandit(raw["bandit"])
    findings += normalize.semgrep(raw["semgrep"])
    findings += normalize.checkov(raw["checkov"])
    findings += normalize.detect_secrets(raw["detect-secrets"])
    return findings
