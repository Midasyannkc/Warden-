"""Agentic SDLC gate. The rule it enforces: code written by an AI is never the thing that
approves it. Approval and the signed check attestation must come from identities the author
(human or agent) does not control."""
from __future__ import annotations

import json
import os
import re

from . import attest, codeowners

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_policy():
    return json.load(open(os.path.join(ROOT, "data/sdlc_policy.json")))


def is_ai_commit(commit: dict, policy: dict) -> bool:
    author = commit["author"].lower()
    if any(p in author for p in policy["ai_author_patterns"]):
        return True
    for key, value in commit.get("trailers", {}).items():
        if key in policy["ai_trailers"] and any(v in value.lower() for v in policy["ai_trailer_values"]):
            return True
    return False


def is_ai_identity(name: str, policy: dict) -> bool:
    return any(p in name.lower() for p in policy["ai_author_patterns"])


def evaluate(pr: dict, policy: dict, rules, keyring: dict) -> dict:
    """pr = {head, commits:[{author, trailers, files}], approvals:[{user, owner_of}], checks, attestation, findings}"""
    reasons, phases = [], {}
    commits = pr["commits"]
    files = sorted({f for c in commits for f in c["files"]})
    sensitive = [f for f in files if codeowners.is_sensitive(rules, f)]
    ai_commits = [c for c in commits if is_ai_commit(c, policy)]
    authors = {c["author"] for c in commits}

    # design
    ok = not sensitive or bool(pr.get("threat_model"))
    phases["design"] = ok
    if not ok:
        reasons.append("sensitive paths changed without a linked threat model: " + ", ".join(sensitive))

    # build
    ok = bool(pr.get("tests_pass"))
    phases["build"] = ok
    if not ok:
        reasons.append("tests did not pass")

    # review
    approvals = pr.get("approvals", [])
    independent = [a for a in approvals if a["user"] not in authors and not is_ai_identity(a["user"], policy)]
    ok = bool(independent) if (ai_commits or sensitive) else bool(approvals)
    if ai_commits and not independent:
        reasons.append("AI-authored change has no approval from an independent human")
    if sensitive:
        needed = {o for f in sensitive for o in codeowners.owners_for(rules, f)}
        have = {o for a in independent for o in a.get("member_of", [])}
        if not needed & have:
            ok = False
            reasons.append("no approval from a code owner of: " + ", ".join(sensitive))
    phases["review"] = ok

    # release
    att = pr.get("attestation")
    att_ok = bool(att) and attest.verify(att, keyring) and att["payload"].get("head") == pr["head"]
    if ai_commits or sensitive:
        if not att_ok:
            reasons.append("missing or invalid signed check attestation for this head commit")
        elif att["key_id"] in pr.get("author_key_ids", []):
            att_ok = False
            reasons.append("attestation was signed by a key the author controls")
        missing = [c for c in policy["required_checks"] if att and att["payload"].get("checks", {}).get(c) != "pass"]
        if att_ok and missing:
            att_ok = False
            reasons.append("required checks not passing in attestation: " + ", ".join(missing))
    crit = [f for f in pr.get("findings", []) if f["severity"] == "critical"]
    if crit:
        reasons.append(f"{len(crit)} critical finding(s) open")
    phases["release"] = (att_ok or not (ai_commits or sensitive)) and not crit

    return {"allow": not reasons, "reasons": reasons, "phases": phases, "ai_commits": len(ai_commits), "sensitive_files": sensitive}


def trailers_from_message(message: str) -> dict:
    out = {}
    for line in message.strip().splitlines()[::-1]:
        m = re.match(r"^([A-Za-z][A-Za-z-]+):\s*(.+)$", line)
        if not m:
            break
        out[m.group(1)] = m.group(2)
    return out
