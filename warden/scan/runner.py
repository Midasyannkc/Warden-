"""Run the real scanners as subprocesses and return normalized Findings.

The raw JSON from each tool is cached under out/ keyed by a hash of the scanned files, so
tests and reports re-run the tools only when the target actually changed. Delete
out/raw_scan_cache.json (or run `make rescan`) to force a fresh run."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile

from . import normalize

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCAN_RECIPE = "v2 detect-secrets --all-files"
CACHE = os.path.join(ROOT, "out", "raw_scan_cache.json")


def _run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env={**os.environ, "BC_SKIP_MAPPING": "TRUE"})


def tree_hash(root: str, target: str) -> str:
    h = hashlib.sha256()
    h.update(SCAN_RECIPE.encode())  # changing how tools are invoked must invalidate cached output
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


def secrets_scan(root: str, target: str) -> dict:
    """--all-files matters: without it detect-secrets lists files with `git ls-files`, so outside
    a git work tree (a CI scratch directory, an exported archive) it prints nothing and exits 0,
    and inside one it skips anything not yet added."""
    p = _run(["detect-secrets", "scan", "--all-files", target], root)
    return json.loads(p.stdout or "{}")


def raw_scan(root: str, target: str) -> dict:
    p = _run(["bandit", "-r", f"{target}/app", "-f", "json", "-q"], root)
    bandit = json.loads(p.stdout or "{}")
    p = _run(["semgrep", "--config", "semgrep_rules", "--metrics=off", "--json", f"{target}/app"], root)
    semgrep = json.loads(p.stdout or "{}")
    p = _run(["checkov", "-d", f"{target}/infra", "--framework", "terraform", "-o", "json", "--quiet"], root)
    checkov = json.loads(p.stdout or "{}")
    checkov = checkov[0] if isinstance(checkov, list) else checkov
    secrets = secrets_scan(root, target)
    return {"bandit": bandit, "semgrep": semgrep, "checkov": checkov, "detect-secrets": secrets}


def _raw_cached(root: str, target: str, use_cache: bool) -> dict:
    key = tree_hash(root, target)
    cache = os.path.join(ROOT, "out", "raw_scan_cache.json")
    store = json.load(open(cache)) if os.path.exists(cache) else {}
    if use_cache and key in store:
        return store[key]
    raw = raw_scan(root, target)
    store[key] = raw
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    json.dump(store, open(cache, "w"))
    return raw


def _normalize(raw: dict) -> list:
    findings = []
    findings += normalize.bandit(raw["bandit"])
    findings += normalize.semgrep(raw["semgrep"])
    findings += normalize.checkov(raw["checkov"])
    findings += normalize.detect_secrets(raw["detect-secrets"])
    return findings


def run_all(root: str = ROOT, target: str = "target", use_cache: bool = True) -> list:
    return _normalize(_raw_cached(root, target, use_cache))


def run_commit(sha: str, use_cache: bool = True) -> list:
    """Scan the target exactly as it was at a past commit, in a scratch directory, with the
    current rules. Using the rules from that commit would hide any rule fix."""
    with tempfile.TemporaryDirectory() as td:
        arc = subprocess.run(["git", "archive", sha, "target"], cwd=ROOT, capture_output=True, check=True)
        subprocess.run(["tar", "-x", "-C", td], input=arc.stdout, check=True)
        shutil.copytree(os.path.join(ROOT, "semgrep_rules"), os.path.join(td, "semgrep_rules"))
        return _normalize(_raw_cached(td, "target", use_cache))
