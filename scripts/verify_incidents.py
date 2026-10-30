"""For every incident, check out its reproduce commit and its fix commit in a scratch worktree and
run the test files that the reproduce commit touched. The reproduce commit must fail and the fix
commit must pass. This is what 'seen to fail for the right reason' means in practice."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sh = lambda *a, cwd=ROOT: subprocess.run(a, cwd=cwd, capture_output=True, text=True)
log = [l.split("|", 1) for l in sh("git", "log", "--reverse", "--format=%h|%s").stdout.strip().splitlines()]
notes = json.load(open(os.path.join(ROOT, "docs/incident_notes.json")))
only = set(map(int, sys.argv[1:]))


def commit_for(n, kind):
    return next(h for h, s in log if s.startswith(f"INC-{n} {kind}:"))


def run_at(sha, files):
    with tempfile.TemporaryDirectory() as td:
        wt = os.path.join(td, "wt")
        sh("git", "worktree", "add", "--detach", wt, sha)
        os.makedirs(os.path.join(wt, "out"), exist_ok=True)
        cache = os.path.join(ROOT, "out/raw_scan_cache.json")
        if os.path.exists(cache):
            shutil.copy(cache, os.path.join(wt, "out/raw_scan_cache.json"))
        p = sh(sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *files, cwd=wt)
        sh("git", "worktree", "remove", "--force", wt)
        return p.returncode, p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-200:]


bad = 0
for x in notes:
    n = x["n"]
    if only and n not in only:
        continue
    r, f = commit_for(n, "reproduce"), commit_for(n, "fix")
    files = [p for p in sh("git", "show", "--name-only", "--format=", r).stdout.split() if p.startswith("tests/test_")]
    rc1, out1 = run_at(r, files)
    rc2, out2 = run_at(f, files)
    ok = rc1 != 0 and rc2 == 0
    bad += not ok
    print(f"INC-{n:<2} {'OK ' if ok else 'BAD'} reproduce[{r}]: {out1} | fix[{f}]: {out2}", flush=True)
sys.exit(1 if bad else 0)
