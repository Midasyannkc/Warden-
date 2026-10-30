from warden.detect import rules as D

EV = D.load_events()
ALERTS = D.run(EV)
BY = {}
for a in ALERTS:
    BY.setdefault(a.rule, []).append(a)
LAB = {e["eventID"]: e for e in EV}


def e(name, **kw):
    base = {"eventID": "t1", "eventTime": "2026-10-28T10:00:00Z", "eventSource": "x", "eventName": name,
            "userIdentity": {"type": "IAMUser", "userName": "u1", "arn": "arn:u1"}, "requestParameters": None,
            "responseElements": None, "additionalEventData": None}
    base.update(kw)
    return base


def test_every_alert_is_a_real_planted_event():
    assert D.score(EV, ALERTS)["precision"] == 1.0


def test_root_login_and_no_mfa():
    assert len(BY["root-console-login"]) == 1
    assert {LAB[i]["userIdentity"]["userName"] for a in BY["console-login-without-mfa"] for i in a.events} == {"root", "marcus"}


def test_failed_login_without_mfa_is_not_alerted():
    assert D.no_mfa([e("ConsoleLogin", responseElements={"ConsoleLogin": "Failure"}, additionalEventData={"MFAUsed": "No"})]) == []


def test_rotating_your_own_key_is_normal():
    own = e("CreateAccessKey", requestParameters={"userName": "u1"})
    assert D.key_for_other([own]) == []
    assert len(D.key_for_other([e("CreateAccessKey", requestParameters={"userName": "someone-else"})])) == 1


def test_public_https_is_not_an_alert_but_public_ssh_is():
    assert len(BY["security-group-open-to-world"]) == 1


def test_ssh_range_that_includes_port_22_is_caught():
    p = {"groupId": "sg", "ipPermissions": {"items": [{"fromPort": 0, "toPort": 65535, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
    assert len(D.open_sg([e("AuthorizeSecurityGroupIngress", requestParameters=p)])) == 1


def test_public_acl_and_policy_both_alert():
    assert len(BY["s3-made-public"]) == 2


def test_logging_tamper_and_guardduty_and_trust_policy():
    assert len(BY["audit-logging-disabled"]) == 2 and len(BY["detection-service-disabled"]) == 1 and len(BY["trust-policy-opened"]) == 1


def test_admin_policy_only_for_administrator_access():
    ok = e("AttachUserPolicy", requestParameters={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
    assert D.admin_policy([ok]) == []


def test_every_rule_names_a_technique():
    assert all(r.meta["technique"].startswith("T1") for r in D.RULES)


def test_bulk_read_alert_lists_every_object_read():
    a = BY["bulk-phi-bucket-read"][0]
    assert len(a.events) == 60, "the scope of a PHI read decides breach notification, so the alert cannot undercount it"


def test_denied_burst_lists_every_denied_call():
    assert len(BY["access-denied-burst"][0].events) == 14


def test_all_planted_events_are_detected():
    assert D.score(EV, ALERTS)["recall"] == 1.0
