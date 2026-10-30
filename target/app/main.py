import hashlib
import json
import time
import hmac
import base64

import requests
import yaml
from flask import Flask, jsonify, request

from . import config, db


def make_app():
    app = Flask(__name__)
    con = db.connect(config.DB_PATH)
    db.seed(con)
    app.config["CON"] = con

    def sign(payload: dict) -> str:
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        mac = hmac.new(config.JWT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        return f"{body}.{mac}"

    def verify(token: str):
        try:
            body, mac = token.split(".")
        except ValueError:
            return None
        good = hmac.new(config.JWT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if mac != good:
            return None
        return json.loads(base64.urlsafe_b64decode(body.encode()))

    def current():
        h = request.headers.get("Authorization", "")
        return verify(h[7:]) if h.startswith("Bearer ") else None

    def forbidden():
        return jsonify(error="forbidden"), 403

    @app.post("/login")
    def login():
        data = request.get_json(force=True)
        pw = hashlib.md5(data.get("password", "").encode()).hexdigest()
        row = con.execute("select id, role from members where email=? and password_md5=?", (data.get("email"), pw)).fetchone()
        if not row:
            return jsonify(error="bad credentials"), 401
        return jsonify(token=sign({"sub": row["id"], "role": row["role"], "exp": time.time() + 3600}))

    @app.get("/members/<int:member_id>")
    def member(member_id):
        user = current()
        if not user:
            return jsonify(error="auth required"), 401
        if user["sub"] != member_id:
            return forbidden()
        row = con.execute("select id, email, name, dob from members where id=?", (member_id,)).fetchone()
        recs = [dict(r) for r in con.execute("select kind, note from records where member_id=?", (member_id,))]
        return jsonify(member=dict(row) if row else None, records=recs)

    @app.get("/members/<int:member_id>/messages")
    def messages(member_id):
        user = current()
        if not user:
            return jsonify(error="auth required"), 401
        if user["sub"] != member_id:
            return forbidden()
        return jsonify(messages=[dict(r) for r in con.execute("select body from messages where member_id=?", (member_id,))])

    @app.get("/search")
    def search():
        user = current()
        if not user:
            return jsonify(error="auth required"), 401
        if user["role"] != "admin":
            return forbidden()
        q = request.args.get("q", "")
        rows = con.execute("select id, name from members where name like ?", (f"%{q}%",)).fetchall()
        return jsonify(results=[dict(r) for r in rows])

    @app.get("/admin/export")
    def export():
        user = current()
        if not user:
            return jsonify(error="auth required"), 401
        if user["role"] != "admin":
            return forbidden()
        return jsonify(members=[dict(r) for r in con.execute("select id, email, name, dob, role from members")])

    @app.post("/import")
    def import_profile():
        if not current():
            return jsonify(error="auth required"), 401
        data = yaml.load(request.get_data(), Loader=yaml.Loader)
        return jsonify(imported=data)

    @app.post("/notify")
    def notify():
        if not current():
            return jsonify(error="auth required"), 401
        r = requests.post(config.VENDOR_WEBHOOK, json=request.get_json(force=True), verify=False, timeout=5)
        return jsonify(status=r.status_code)

    return app
