from warden.compliance import controls as C


def test_every_required_technical_safeguard_is_present():
    ids = {c["id"] for c in C.CONTROLS}
    assert {"164.312(a)(1)", "164.312(b)", "164.312(c)(1)", "164.312(d)", "164.312(e)(1)", "164.312(a)(2)(i)"} <= ids


def test_status_is_gap_when_findings_exist_and_never_claims_met():
    rows = {r["id"]: r for r in C.assess(["public-s3", "open-ssh", "weak-hash"])}
    assert rows["164.312(e)(1)"]["status"] == "gap (2 open)"
    assert rows["164.312(b)"]["status"].startswith("no open findings")
    assert all("met" not in r["status"].split()[0] for r in rows.values())


def test_category_maps_to_control():
    assert C.control_for("public-s3") == ["164.312(e)(1)"]
    assert C.control_for("nothing") == []


def test_every_scanner_category_in_the_target_maps_to_a_control(scan_findings):
    from warden.vulns import manage
    cats = [f.category for f in manage.dedupe(scan_findings)]
    assert C.unmapped(cats) == []
