def test_real_scanners_find_seeded_flaws(scan_findings):
    cats = {f.category for f in scan_findings}
    for expected in ["sql-injection", "unsafe-deserialization", "hardcoded-secret", "public-s3", "open-ssh", "iam-wildcard", "rds-public"]:
        assert expected in cats, expected
    assert {f.tool for f in scan_findings} == {"bandit", "semgrep", "checkov", "detect-secrets"}


def test_fingerprint_ignores_line_numbers():
    from warden.model import Finding
    a = Finding("semgrep", "r", "high", "t", "a.py", 10, category="sql-injection", resource="sql-injection")
    b = Finding("semgrep", "r", "high", "t", "a.py", 99, category="sql-injection", resource="sql-injection")
    assert a.fingerprint == b.fingerprint
