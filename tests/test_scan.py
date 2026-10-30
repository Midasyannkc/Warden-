def test_real_scanners_find_seeded_flaws(baseline_findings):
    scan_findings = baseline_findings
    cats = {f.category for f in scan_findings}
    for expected in ["sql-injection", "unsafe-deserialization", "hardcoded-secret", "public-s3", "open-ssh", "iam-wildcard", "rds-public"]:
        assert expected in cats, expected
    assert {f.tool for f in scan_findings} == {"bandit", "semgrep", "checkov", "detect-secrets"}


def test_fingerprint_ignores_line_numbers():
    from warden.model import Finding
    a = Finding("semgrep", "r", "high", "t", "a.py", 10, category="sql-injection", resource="sql-injection")
    b = Finding("semgrep", "r", "high", "t", "a.py", 99, category="sql-injection", resource="sql-injection")
    assert a.fingerprint == b.fingerprint


def test_secret_scanner_works_outside_a_git_tree(tmp_path):
    from warden.scan import runner
    d = tmp_path / "target" / "app"
    d.mkdir(parents=True)
    (d / "leak.py").write_text('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')
    raw = runner.secrets_scan(str(tmp_path), "target")
    assert raw["results"], "a planted credential must be found even when the directory is not a repository"


def test_remediated_tree_has_no_secret_findings(scan_findings):
    leaked = [(f.file, f.line, f.rule) for f in scan_findings if f.category == "hardcoded-secret"]
    assert leaked == [], "the remediated target should be clean; an allowlist belongs on a verified false positive only"


def test_allowlist_does_not_hide_real_secrets(baseline_findings):
    assert sum(1 for f in baseline_findings if f.category == "hardcoded-secret") >= 4
