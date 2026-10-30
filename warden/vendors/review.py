"""Vendor review: check every security claim against the evidence before PHI flows.

The reviewer does not take marketing at face value. A claim only counts if a document
backs it, and a phrase like "HIPAA compliant" never counts on its own, because no
certification by that name exists; a signed BAA does."""
from __future__ import annotations

import datetime as dt
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Which data classes each purpose genuinely needs. Anything beyond is over-collection.
NEEDED = {
    "book appointments": {"name", "phone", "appointment time"},
    "visit transcription": {"audio", "transcript", "name", "diagnosis"},
    "cohort analytics": {"de-identified claims"},
    "deliver lab results to chart": {"lab results", "member id"},
    "answer member questions": {"name", "email"},
}
PHI = {"diagnosis", "symptoms", "lab results", "audio", "transcript", "name", "phone", "email", "member id", "appointment time"}
US_ONLY = True


def load():
    return json.load(open(os.path.join(ROOT, "data/vendor_dossiers.json")))


def finding(sev, area, text, fix):
    return {"severity": sev, "area": area, "finding": text, "condition": fix}


def review(v: dict, today: dt.date) -> dict:
    ev, claims = v["evidence"], [c.lower() for c in v["claims"]]
    out = []
    has = lambda *words: any(all(w in c for w in words) for c in claims)

    # SOC 2
    soc = ev.get("soc2")
    if has("soc 2") or has("soc2"):
        if not soc:
            out.append(finding("high", "SOC 2", "claims SOC 2 but no report was provided", "obtain the report or treat as unaudited"))
        else:
            age = (today - dt.date.fromisoformat(soc["period_end"])).days
            if soc["type"] != "II":
                out.append(finding("high", "SOC 2", f"claims Type II but the report is Type {soc['type']}", "require Type II before PHI"))
            if age > 365:
                out.append(finding("medium", "SOC 2", f"report period ended {age} days ago", "obtain a current report or bridge letter"))
            if not soc["covers_product"]:
                out.append(finding("high", "SOC 2", "report scope does not include the product we would use", "require in-scope report"))
            if soc["exceptions"]:
                out.append(finding("low", "SOC 2", f"{soc['exceptions']} exception(s) noted", "review exceptions with the vendor"))
    elif not soc:
        out.append(finding("medium", "SOC 2", "no SOC 2 report", "request report or compensating evidence"))

    # HIPAA
    if not ev["baa_signed"]:
        out.append(finding("critical", "HIPAA", "no signed BAA", "no PHI until a BAA is signed"))
    if has("hipaa compliant"):
        out.append(finding("low", "HIPAA", "'HIPAA compliant' is not a certification", "rely on the BAA and evidence, not the phrase"))

    # retention
    if has("zero", "retention") and ev["retention_days"] > 0:
        out.append(finding("high", "Retention", f"claims zero retention but contract keeps data {ev['retention_days']} days", "require ZDR in writing or accept and document the retention"))
    elif ev["retention_days"] > 90:
        out.append(finding("medium", "Retention", f"retains data {ev['retention_days']} days", "negotiate retention to the minimum needed"))

    # training
    if (has("never train") or has("no training")) and not ev["training_opt_out_in_contract"]:
        out.append(finding("high", "AI training", "claims no training but the contract has no such clause", "add a no-training clause to the DPA"))

    # subprocessors
    for s in ev.get("subprocessors", []):
        if US_ONLY and s["country"] != "US":
            out.append(finding("medium", "Subprocessors", f"{s['name']} operates in {s['country']}", "confirm BAA flow-down and data residency"))
    if ev.get("encryption_at_rest") in (None, "unknown"):
        out.append(finding("medium", "Encryption", "encryption at rest not evidenced", "obtain written confirmation"))
    if ev.get("pen_test_date"):
        age = (today - dt.date.fromisoformat(ev["pen_test_date"])).days
        if age > 365:
            out.append(finding("medium", "Pen test", f"last pen test {age} days ago", "request a current report"))
    else:
        out.append(finding("medium", "Pen test", "no pen test evidence", "request a recent report"))

    # data flows: minimize
    for f in v["data_flows"]:
        extra = sorted(set(f["data"]) - NEEDED.get(f["purpose"], set()))
        if extra and set(extra) & PHI:
            out.append(finding("high", "Data flow", f"sends {', '.join(extra)} beyond what '{f['purpose']}' needs", "strip with DLP before the call"))

    sev = {f["severity"] for f in out}
    verdict = "reject" if "critical" in sev else "approve with conditions" if sev & {"high", "medium"} else "approve"
    return {"vendor": v["name"], "category": v["category"], "verdict": verdict, "findings": out}


def review_all(data=None, today=None):
    data = data or load()
    today = today or dt.date.fromisoformat(data["review_date"])
    return [review(v, today) for v in data["vendors"]]


def exec_summary(r: dict) -> str:
    n = {s: sum(1 for f in r["findings"] if f["severity"] == s) for s in ["critical", "high", "medium", "low"]}
    why = "; ".join(f["finding"] for f in r["findings"] if f["severity"] in ("critical", "high")[:2]) or "no blocking issues"
    return f"{r['vendor']}: {r['verdict'].upper()}. {n['critical']} critical, {n['high']} high. {why}."


def engineer_checklist(r: dict) -> list[str]:
    return [f"[{f['severity']}] {f['area']}: {f['condition']}" for f in r["findings"] if f["severity"] != "low"]
