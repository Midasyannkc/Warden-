import datetime as dt
from warden.scan import runner
from warden.vulns import manage


def test_kev_beats_cvss_for_priority_and_sla():
    import json, os
    kev = manage.load_kev()
    sbom = json.load(open(os.path.join(manage.ROOT, "data/sbom.json")))
    fs = manage.sbom_findings(sbom, kev)
    by = {f.resource.split(":")[1]: f for f in fs}
    assert by["CVE-2021-44228"].kev and by["CVE-2021-23337"].kev is False
    assert manage.priority(by["CVE-2021-44228"]) > manage.priority(by["CVE-2021-23337"])
    assert manage.sla_days(by["CVE-2014-0160"]) == 7  # lower CVSS but known exploited
    assert manage.sla_days(by["CVE-2021-23337"]) == 30


def test_overdue_uses_due_date():
    import json, os
    kev = manage.load_kev()
    sbom = json.load(open(os.path.join(manage.ROOT, "data/sbom.json")))
    rows = manage.assign_sla(manage.sbom_findings(sbom, kev), dt.date(2026, 10, 1))
    late = manage.overdue(rows, dt.date(2026, 10, 15))
    assert late and all(r["kev"] for r in late)


def test_recurring_findings_become_guardrails():
    from warden.model import Finding
    mk = lambda c: Finding("t", c, "high", c, "f", category=c, resource=c)
    hist = [[mk("sql-injection"), mk("x")], [mk("sql-injection")], [mk("sql-injection"), mk("y")]]
    fb = manage.feedback(hist)
    assert fb[0]["category"] == "sql-injection" and fb[0]["scans"] == 3 and "parameterized" in fb[0]["guardrail"]
