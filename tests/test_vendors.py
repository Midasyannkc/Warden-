import datetime as dt

from warden.vendors import review as V

TODAY = dt.date(2026, 10, 29)
BY = {r["vendor"]: r for r in V.review_all()}


def areas(name, sev=None):
    return {f["area"] for f in BY[name]["findings"] if sev is None or f["severity"] == sev}


def test_chatbubble_without_baa_is_rejected():
    assert BY["ChatBubble"]["verdict"] == "reject"
    assert any(f["severity"] == "critical" and f["area"] == "HIPAA" for f in BY["ChatBubble"]["findings"])


def test_scribenote_marketing_claims_are_contradicted_by_evidence():
    a = areas("ScribeNote", "high")
    assert {"SOC 2", "Retention", "AI training"} <= a
    assert BY["ScribeNote"]["verdict"] == "approve with conditions"


def test_hipaa_compliant_phrase_alone_never_counts():
    assert "HIPAA" in areas("ScribeNote") and any("not a certification" in f["finding"] for f in BY["ScribeNote"]["findings"])


def test_scheduler_gets_dlp_condition_for_diagnosis():
    f = [x for x in BY["SlotPilot"]["findings"] if x["area"] == "Data flow"]
    assert f and "diagnosis" in f[0]["finding"] and "DLP" in f[0]["condition"]


def test_expired_out_of_scope_soc2_is_flagged():
    msgs = " ".join(f["finding"] for f in BY["InsightGateway"]["findings"])
    assert "scope" in msgs and "days ago" in msgs


def test_clean_vendor_is_approved():
    assert BY["LabBridge"]["verdict"] == "approve"


def test_non_us_subprocessor_is_flagged():
    assert "Subprocessors" in areas("ScribeNote")


def test_outputs_for_both_audiences():
    s = V.exec_summary(BY["ChatBubble"])
    assert s.startswith("ChatBubble: REJECT") and "no signed BAA" in s
    assert all(line.startswith("[") for line in V.engineer_checklist(BY["ScribeNote"]))


def test_soc2_report_exactly_one_year_old_is_still_current():
    v = {"name": "x", "category": "c", "claims": ["SOC 2 Type II"], "data_flows": [],
         "evidence": {"soc2": {"type": "II", "period_end": "2025-10-29", "covers_product": True, "exceptions": 0}, "baa_signed": True,
                      "retention_days": 0, "training_opt_out_in_contract": True, "subprocessors": [], "encryption_at_rest": "AES-256", "pen_test_date": "2026-09-01"}}
    assert V.review(v, TODAY)["findings"] == []
