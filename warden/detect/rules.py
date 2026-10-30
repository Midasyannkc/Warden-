"""Detection rules over CloudTrail records. Each rule names the ATT&CK technique and the
HIPAA control it supports, and returns alerts that point back at the triggering events."""
from __future__ import annotations

import datetime as dt
import json
import os
from collections import defaultdict
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES = []


@dataclass
class Alert:
    rule: str
    severity: str
    summary: str
    events: list
    technique: str


def rule(name, severity, technique):
    def deco(fn):
        fn.meta = {"name": name, "severity": severity, "technique": technique}
        RULES.append(fn)
        return fn
    return deco


def t(e):
    return dt.datetime.strptime(e["eventTime"], "%Y-%m-%dT%H:%M:%SZ")


def who(e):
    return e["userIdentity"].get("userName") or e["userIdentity"].get("arn")


def alert(fn, e, summary):
    return Alert(fn.meta["name"], fn.meta["severity"], summary, [e["eventID"]], fn.meta["technique"])


@rule("root-console-login", "critical", "T1078.004")
def root_login(events):
    return [alert(root_login, e, "root account console login") for e in events
            if e["eventName"] == "ConsoleLogin" and e["userIdentity"]["type"] == "Root"]


@rule("console-login-without-mfa", "high", "T1078.004")
def no_mfa(events):
    return [alert(no_mfa, e, f"{who(e)} signed in without MFA") for e in events
            if e["eventName"] == "ConsoleLogin" and (e.get("responseElements") or {}).get("ConsoleLogin") == "Success"
            and (e.get("additionalEventData") or {}).get("MFAUsed") == "No"]


@rule("access-key-created-for-other-user", "high", "T1098.001")
def key_for_other(events):
    return [alert(key_for_other, e, f"{who(e)} created an access key for {e['requestParameters']['userName']}") for e in events
            if e["eventName"] == "CreateAccessKey" and e["requestParameters"].get("userName") != e["userIdentity"].get("userName")]


@rule("admin-policy-attached", "critical", "T1098")
def admin_policy(events):
    return [alert(admin_policy, e, f"{who(e)} attached an administrator policy") for e in events
            if e["eventName"] in {"AttachUserPolicy", "AttachRolePolicy"} and (e["requestParameters"] or {}).get("policyArn", "").endswith("/AdministratorAccess")]


@rule("s3-made-public", "critical", "T1530")
def public_bucket(events):
    out = []
    for e in events:
        p = e.get("requestParameters") or {}
        if e["eventName"] == "PutBucketAcl" and "AllUsers" in json.dumps(p):
            out.append(alert(public_bucket, e, f"bucket {p['bucketName']} ACL grants AllUsers"))
        if e["eventName"] == "PutBucketPolicy" and '"Principal":"*"' in str(p.get("policy", "")):
            out.append(alert(public_bucket, e, f"bucket {p['bucketName']} policy allows any principal"))
    return out


@rule("audit-logging-disabled", "critical", "T1562.008")
def logging_off(events):
    return [alert(logging_off, e, f"{who(e)} ran {e['eventName']}") for e in events if e["eventName"] in {"StopLogging", "DeleteTrail"}]


@rule("security-group-open-to-world", "high", "T1190")
def open_sg(events):
    out = []
    for e in events:
        if e["eventName"] != "AuthorizeSecurityGroupIngress":
            continue
        for perm in e["requestParameters"]["ipPermissions"]["items"]:
            world = any(r["cidrIp"] == "0.0.0.0/0" for r in perm["ipRanges"]["items"])
            if world and perm["fromPort"] <= 22 <= perm["toPort"]:
                out.append(alert(open_sg, e, f"{e['requestParameters']['groupId']} opens SSH to the internet"))
    return out


@rule("trust-policy-opened", "critical", "T1098")
def trust_open(events):
    return [alert(trust_open, e, "role trust policy allows any principal") for e in events
            if e["eventName"] == "UpdateAssumeRolePolicy" and '"AWS":"*"' in str(e["requestParameters"].get("policyDocument", ""))]


@rule("detection-service-disabled", "high", "T1562.001")
def guardduty_off(events):
    return [alert(guardduty_off, e, f"{who(e)} deleted a GuardDuty detector") for e in events if e["eventName"] in {"DeleteDetector", "StopMonitoringMembers"}]


def window(events, pick, minutes, count):
    """Principals with at least `count` matching events inside any `minutes` window."""
    by = defaultdict(list)
    for e in events:
        if pick(e):
            by[who(e)].append(e)
    hits = []
    for user, es in by.items():
        es.sort(key=t)
        i = 0
        members: dict[str, dict] = {}
        for j, e in enumerate(es):
            while t(e) - t(es[i]) > dt.timedelta(minutes=minutes):
                i += 1
            if j - i + 1 >= count:
                # keep every event inside any qualifying window so the alert shows the full scope
                for x in es[i:j + 1]:
                    members[x["eventID"]] = x
        if members:
            hits.append((user, sorted(members.values(), key=t)))
    return hits


@rule("bulk-phi-bucket-read", "critical", "T1530")
def bulk_read(events):
    pick = lambda e: e["eventName"] == "GetObject" and "phi" in (e["requestParameters"] or {}).get("bucketName", "")
    return [Alert("bulk-phi-bucket-read", "critical", f"{u} read {len(es)} PHI objects in 5 minutes", [x["eventID"] for x in es], "T1530")
            for u, es in window(events, pick, 5, 50)]


@rule("access-denied-burst", "medium", "T1087.004")
def denied_burst(events):
    pick = lambda e: e.get("errorCode") == "AccessDenied"
    return [Alert("access-denied-burst", "medium", f"{u} hit AccessDenied {len(es)} times in 10 minutes", [x["eventID"] for x in es], "T1087.004")
            for u, es in window(events, pick, 10, 10)]


def load_events():
    return json.load(open(os.path.join(ROOT, "data/cloudtrail_events.json")))["events"]


def run(events=None):
    events = events if events is not None else load_events()
    out = []
    for r in RULES:
        out += r(events)
    return out


def score(events, alerts):
    """Event-level precision and recall against the hidden _label."""
    label = {e["eventID"]: e["_label"] for e in events}
    flagged = {i for a in alerts for i in a.events}
    truth = {i for i, l in label.items() if l}
    tp = len(flagged & truth)
    return {"alerts": len(alerts), "precision": round(tp / len(flagged), 3) if flagged else 0.0,
            "recall": round(tp / len(truth), 3), "missed": sorted(label[i] for i in truth - flagged),
            "false_positives": sorted(flagged - truth)}
