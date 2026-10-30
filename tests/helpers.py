from target.app.main import make_app


def client():
    app = make_app()
    app.testing = True
    return app.test_client()


def login(c, email, pw):
    r = c.post("/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.data
    return {"Authorization": "Bearer " + r.get_json()["token"]}


def as_member(c):
    return login(c, "ada@example.test", "pw-ada")


def as_admin(c):
    return login(c, "admin@example.test", "pw-admin")
