"""Non-human identity (NHI) analyzer: find the credentials that nobody owns, nobody uses,
or that can do far more than their job needs."""
from __future__ import annotations

import datetime as dt
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STALE_DAYS = 90
MAX_KEY_AGE = 180
ESCALATION = {"iam:passrole", "iam:createaccesskey", "iam:attachuserpolicy", "iam:putuserpolicy",
              "iam:createpolicyversion", "iam:updateassumerolepolicy", "iam:attachrolepolicy"}
BROAD_SCOPES = {"administration:write", "okta.groups.manage", "https://www.googleapis.com/auth/drive", "files:write"}
SEV_ORDER = ["low", "medium", "high", "critical"]


def load(name):
    return json.load(open(os.path.join(ROOT, "data", name)))


def actions_of(policy: dict) -> list[tuple[str, str]]:
    out = []
    for st in policy.get("Statement", []):
        if st.get("Effect") != "Allow":
            continue
        acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
        res = st["Resource"] if isinstance(st["Resource"], str) else ",".join(st["Resource"])
        out += [(a, res) for a in acts]
    return out


def analyze(identity: dict, roster: set, today: dt.date) -> list[dict]:
    issues = []

    def add(rule, sev, why):
        issues.append({"id": identity["id"], "name": identity["name"], "rule": rule, "severity": sev, "why": why})

    last = dt.date.fromisoformat(identity["last_used"])
    created = dt.date.fromisoformat(identity["created"])
    if (today - last).days > STALE_DAYS:
        add("stale", "medium", f"unused for {(today - last).days} days")
    if identity["kind"] in {"iam_user_key", "api_token"} and (today - created).days > MAX_KEY_AGE:
        add("old-credential", "medium", f"credential is {(today - created).days} days old, limit {MAX_KEY_AGE}")
    if identity.get("owner") not in roster:
        add("orphaned", "high", f"owner {identity.get('owner')!r} is not an active employee")
    for act, res in actions_of(identity.get("policy", {})):
        a = act.lower()
        if a == "*" and res == "*":
            add("admin-wildcard", "critical", "Allow * on *")
        elif a.endswith(":*") and res == "*":
            add("service-wildcard", "high", f"{act} on every resource")
        elif a in ESCALATION:
            add("privilege-escalation", "high", f"{act} allows privilege escalation")
    for s in identity.get("scopes", []):
        if s in BROAD_SCOPES:
            add("over-scoped", "high", f"scope {s} is broader than a typical integration needs")
    return issues


def analyze_all(inv: dict, roster: dict, today: dt.date | None = None) -> list[dict]:
    today = today or dt.date.fromisoformat(inv["as_of"])
    active = set(roster["active"])
    out = []
    for i in inv["identities"]:
        out += analyze(i, active, today)
    return out


def risk_by_identity(issues: list[dict]) -> list[dict]:
    pts = {"low": 1, "medium": 3, "high": 6, "critical": 10}
    agg: dict = {}
    for i in issues:
        a = agg.setdefault(i["id"], {"id": i["id"], "name": i["name"], "score": 0, "rules": []})
        a["score"] += pts[i["severity"]]
        a["rules"].append(i["rule"])
    return sorted(agg.values(), key=lambda a: -a["score"])
