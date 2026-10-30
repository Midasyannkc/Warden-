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
