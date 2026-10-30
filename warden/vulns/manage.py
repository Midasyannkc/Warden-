"""Vulnerability management: dedupe, prioritize with CISA KEV, SLA clocks, and the
recurring-issue feedback loop that turns repeat findings into development guardrails."""
from __future__ import annotations

import datetime as dt
import json
import os
from collections import Counter, defaultdict

from ..model import Finding, SEVERITIES

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Internal remediation policy (days). KEV entries get the shortest clock regardless of CVSS.
SLA_DAYS = {"kev": 7, "critical": 15, "high": 30, "medium": 90, "low": 180, "info": 365}


def load_kev(path=None) -> dict:
    path = path or os.path.join(ROOT, "data/raw/kev.json")
    return {v["cveID"]: v for v in json.load(open(path))["vulnerabilities"]}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a fingerprint, keeping the highest severity and
    remembering every tool that reported it."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.fingerprint].append(f)
    out = []
    for fp, items in groups.items():
        best = max(items, key=lambda f: SEVERITIES.index(f.severity))
        best.extra = {**best.extra, "tools": sorted({i.tool for i in items}), "rules": sorted({i.rule for i in items})}
        out.append(best)
    return out


def sbom_findings(sbom: dict, kev: dict) -> list[Finding]:
    out = []
    for c in sbom["components"]:
        if not c.get("cve"):
            continue
        cvss = c.get("cvss") or 0
        sev = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium"
        f = Finding("sbom", c["cve"], sev, f"{c['name']} {c['version']} is affected by {c['cve']}", c["service"], 0,
                    "", "vulnerable-dependency", resource=f"{c['name']}:{c['cve']}")
        f.kev = c["cve"] in kev
        f.extra = {"cvss": cvss, "exposure": c["exposure"], "component": c["name"], "version": c["version"]}
        if f.kev:
            k = kev[c["cve"]]
            f.extra.update(kev_added=k["dateAdded"], kev_due=k["dueDate"], ransomware=k["knownRansomwareCampaignUse"])
        out.append(f)
    return out


def priority(f: Finding) -> int:
    """Higher means fix sooner. KEV beats everything, then internet exposure, then severity."""
    score = SEVERITIES.index(f.severity) * 10
    if f.kev:
        score += 100
    if f.extra.get("ransomware") == "Known":
        score += 20
    if f.extra.get("exposure") == "internet":
        score += 15
    return score


def sla_days(f: Finding) -> int:
    return SLA_DAYS["kev"] if f.kev else SLA_DAYS[f.severity]


def assign_sla(findings: list[Finding], opened: dt.date) -> list[dict]:
    rows = []
    for f in sorted(findings, key=priority, reverse=True):
        f.sla_days = sla_days(f)
        rows.append({**f.to_dict(), "priority": priority(f), "opened": opened.isoformat(),
                     "due": (opened + dt.timedelta(days=f.sla_days)).isoformat()})
    return rows


def overdue(rows: list[dict], today: dt.date) -> list[dict]:
    return [r for r in rows if dt.date.fromisoformat(r["due"]) < today and r.get("status", "open") == "open"]


def recurring(history: list[list[Finding]], threshold: int = 2) -> list[tuple[str, int]]:
    """Categories that show up in `threshold` or more separate scans become guardrail candidates."""
    seen = Counter()
    for scan in history:
        for cat in {f.category for f in scan}:
            seen[cat] += 1
    return [(c, n) for c, n in seen.most_common() if n >= threshold]


GUARDRAILS = {
    "broken-object-authorization": "Add an ownership check helper and a Semgrep rule that fails CI on id-parameter routes without it.",
    "sql-injection": "Ban string-built SQL with a Semgrep rule; require parameterized queries.",
    "hardcoded-secret": "Enable push protection and move secrets to a secrets manager; rotate anything that was committed.",
    "unsafe-deserialization": "Require yaml.safe_load; fail CI on yaml.load with the full Loader.",
    "public-s3": "Enforce an account-level S3 Block Public Access guardrail and a Terraform module default.",
    "iam-wildcard": "Require IAM policies from a reviewed module; block Action * in CI.",
    "open-ssh": "Remove inbound SSH; use SSM Session Manager instead.",
}


def feedback(history: list[list[Finding]]) -> list[dict]:
    return [{"category": c, "scans": n, "guardrail": GUARDRAILS.get(c, "Add a lint or policy check for this class.")}
            for c, n in recurring(history)]
