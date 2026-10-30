"""The target's Terraform is scanned by the real Checkov; these tests read its results."""


def infra(scan_findings):
    return [f for f in scan_findings if f.tool == "checkov"]


def test_no_high_risk_infrastructure_findings(scan_findings):
    high = sorted({(f.category, f.resource) for f in infra(scan_findings) if f.severity == "high"})
    assert high == []


def test_known_dangerous_patterns_are_gone(scan_findings):
    cats = {f.category for f in infra(scan_findings)}
    assert not cats & {"public-s3", "open-ssh", "rds-public", "rds-encryption", "iam-wildcard", "eks-public-endpoint", "eks-logging"}


def test_infrastructure_findings_dropped_by_at_least_three_quarters(scan_findings):
    assert len(infra(scan_findings)) <= 11  # 44 before the rewrite
