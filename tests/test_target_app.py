"""Behavior tests for the CareLoop member API. Tests that begin as exploits are added in the
reproduce commit of an incident and pass after its fix commit."""
from tests.helpers import client, login, as_member, as_admin


def test_member_can_read_own_record():
    c = client()
    r = c.get("/members/1", headers=as_member(c))
    assert r.status_code == 200 and r.get_json()["member"]["name"] == "Ada Rowan"


def test_login_rejects_bad_password():
    c = client()
    assert c.post("/login", json={"email": "ada@example.test", "password": "nope"}).status_code == 401


def test_unauthenticated_request_is_rejected():
    assert client().get("/members/1").status_code == 401


def test_member_cannot_read_another_members_record():
    c = client()
    r = c.get("/members/2", headers=as_member(c))
    assert r.status_code == 403
    assert b"Crohn" not in r.data


def test_member_cannot_read_another_members_messages():
    c = client()
    r = c.get("/members/2/messages", headers=as_member(c))
    assert r.status_code == 403 and b"prescription" not in r.data


def test_search_treats_input_as_data_not_sql():
    c = client()
    r = c.get("/search", query_string={"q": "' OR '1'='1"}, headers=as_admin(c))
    assert r.get_json()["results"] == []


def test_admin_search_still_finds_members_by_name():
    c = client()
    r = c.get("/search", query_string={"q": "Ada"}, headers=as_admin(c))
    assert [m["name"] for m in r.get_json()["results"]] == ["Ada Rowan"]


def test_member_cannot_search_the_member_directory():
    c = client()
    assert c.get("/search", query_string={"q": "a"}, headers=as_member(c)).status_code == 403


def test_member_cannot_export_the_member_table():
    c = client()
    r = c.get("/admin/export", headers=as_member(c))
    assert r.status_code == 403 and b"admin@example.test" not in r.data


def test_admin_can_export():
    c = client()
    r = c.get("/admin/export", headers=as_admin(c))
    assert r.status_code == 200 and len(r.get_json()["members"]) == 4


def test_debug_endpoint_does_not_exist_and_leaks_nothing():
    c = client()
    r = c.get("/debug")
    assert r.status_code == 404 and b"PATH" not in r.data and b"careloop-signing-key" not in r.data


def test_import_accepts_plain_yaml():
    c = client()
    r = c.post("/import", data="name: Ada\ncity: Dallas\n", headers=as_member(c))
    assert r.status_code == 200 and r.get_json()["imported"] == {"name": "Ada", "city": "Dallas"}


def test_import_refuses_yaml_that_constructs_python_objects():
    c = client()
    r = c.post("/import", data="!!python/object/apply:builtins.len [[1, 2, 3]]", headers=as_member(c))
    assert r.status_code == 400, "a payload that calls a Python function must not be evaluated"


def test_vendor_call_verifies_tls_and_has_a_timeout(monkeypatch):
    seen = {}

    class R:
        status_code = 202

    def fake_post(url, **kw):
        seen.update(kw)
        return R()

    monkeypatch.setattr("target.app.main.requests.post", fake_post)
    c = client()
    r = c.post("/notify", json={"msg": "hi"}, headers=as_member(c))
    assert r.status_code == 200
    assert seen.get("verify", True) is True and seen.get("timeout")
