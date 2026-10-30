"""Map technical evidence to HIPAA Security Rule technical safeguards (45 CFR 164.312, plus the
administrative safeguards a security engineer evidences), with SOC 2 and NIST CSF 2.0 tags.

A control is never marked "met" from Warden's output alone: it is either a gap with the
findings that cause it, or "no open findings" meaning the technical checks here found nothing.
Policies, training and the rest of the program are outside what code can evidence."""
from __future__ import annotations

CONTROLS = [
    {"id": "164.312(a)(1)", "title": "Access control", "type": "required", "soc2": "CC6.1, CC6.3", "csf": "PR.AA",
     "categories": ["broken-object-authorization", "missing-function-authorization", "iam-wildcard", "iam-privilege-escalation",
                    "iam-wildcard-assume", "iam-write-without-constraint", "iam-credentials-exposure", "iam-data-exfiltration", "nhi-admin-wildcard",
                    "nhi-service-wildcard", "nhi-privilege-escalation", "nhi-over-scoped", "rds-iam-auth"]},
    {"id": "164.312(a)(2)(i)", "title": "Unique user identification", "type": "required", "soc2": "CC6.1", "csf": "PR.AA",
     "categories": ["nhi-orphaned", "hardcoded-secret"]},
    {"id": "164.312(a)(2)(iv)", "title": "Encryption and decryption", "type": "addressable", "soc2": "CC6.1, CC6.7", "csf": "PR.DS",
     "categories": ["s3-encryption", "rds-encryption", "eks-secrets-encryption"]},
    {"id": "164.312(b)", "title": "Audit controls", "type": "required", "soc2": "CC7.2", "csf": "DE.CM",
     "categories": ["s3-logging", "eks-logging", "no-cloudtrail", "rds-logging", "rds-monitoring"]},
    {"id": "164.312(c)(1)", "title": "Integrity", "type": "required", "soc2": "CC7.1, CC8.1", "csf": "PR.DS",
     "categories": ["s3-versioning", "vulnerable-dependency", "unsafe-deserialization", "rds-resilience", "rds-multiaz"]},
    {"id": "164.312(d)", "title": "Person or entity authentication", "type": "required", "soc2": "CC6.1", "csf": "PR.AA",
     "categories": ["weak-hash", "nhi-stale", "nhi-old-credential"]},
    {"id": "164.312(e)(1)", "title": "Transmission security", "type": "addressable", "soc2": "CC6.6, CC6.7", "csf": "PR.DS",
     "categories": ["tls-verification-disabled", "open-ssh", "eks-public-endpoint", "eks-public-cidr", "rds-public", "public-s3", "sg-hygiene", "open-egress"]},
    {"id": "164.308(a)(1)(ii)(A)", "title": "Risk analysis", "type": "required", "soc2": "CC3.2, CC4.1", "csf": "ID.RA",
     "categories": ["sql-injection"]},
]


def control_for(category: str):
    return [c["id"] for c in CONTROLS if category in c["categories"]]


def assess(finding_categories: list[str]) -> list[dict]:
    """finding_categories: one entry per open finding (a category may repeat)."""
    rows = []
    for c in CONTROLS:
        n = sum(1 for k in finding_categories if k in c["categories"])
        rows.append({**{k: c[k] for k in ("id", "title", "type", "soc2", "csf")}, "open_findings": n,
                     "status": f"gap ({n} open)" if n else "no open findings from technical checks"})
    return rows


def unmapped(finding_categories: list[str]) -> list[str]:
    return sorted({k for k in finding_categories if not control_for(k)})
