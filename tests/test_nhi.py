import datetime as dt
from warden.nhi import analyze as A

INV = A.load("nhi_inventory.json")
ROSTER = A.load("hr_roster.json")


def rules_for(name):
    return {i["rule"] for i in A.analyze_all(INV, ROSTER) if i["name"] == name}


def test_clean_scoped_key_has_no_issues():
    assert rules_for("svc-report-batch") == set()


def test_legacy_admin_key_is_flagged_every_way():
    assert {"stale", "old-credential", "orphaned", "admin-wildcard"} <= rules_for("svc-legacy-etl")


def test_runtime_role_has_privilege_escalation_and_s3_wildcard():
    assert {"service-wildcard", "privilege-escalation"} <= rules_for("app-runtime-role")


def test_oauth_grant_of_departed_employee_is_orphaned_and_over_scoped():
    assert {"orphaned", "over-scoped"} <= rules_for("ai-notetaker")


def test_ownerless_key_is_orphaned():
    assert "orphaned" in rules_for("svc-analytics-export")


def test_risk_ranking_puts_admin_key_first():
    ranked = A.risk_by_identity(A.analyze_all(INV, ROSTER))
    assert ranked[0]["name"] == "svc-legacy-etl"
