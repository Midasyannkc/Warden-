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
