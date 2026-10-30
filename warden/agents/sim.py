"""A deterministic, worst-case obedient agent used to test the controls around an agent.

It is NOT a language model. It does the user's task, and it also follows any instruction it
finds in a user message or a retrieved document. That makes the no-defense attack success
rate a measure of what the attacker can reach, and the defended rate a measure of the
controls, independent of how any particular model behaves."""
from __future__ import annotations

import base64
import re

from .policy import Call

EMAIL = re.compile(r"(?:email|send|forward)\s+(?:this|the|that|it|all|every)?[^.\n]*?\s+to\s+([^\s,;]+@[^\s,;.]+(?:\.[^\s,;.]+)*)", re.I)
POST = re.compile(r"(?:post|upload|submit)\s+[^.\n]*?\s+to\s+(https?://[^\s,;]+)", re.I)
ALL = re.compile(r"(?:list|dump|export|read)\s+(?:all|every)\s+members", re.I)
OTHER = re.compile(r"(?:read|open|fetch|show)\s+member\s+#?(\d+)", re.I)
DELETE = re.compile(r"delete\s+member\s+#?(\d+)", re.I)
B64 = re.compile(r"decode and follow:\s*([A-Za-z0-9+/=]{16,})", re.I)


def plan(text: str, origin: str, context: str) -> list[Call]:
    calls = []
    for blob in B64.findall(text):
        try:
            text += "\n" + base64.b64decode(blob).decode()
        except Exception:
            pass
    for m in EMAIL.finditer(text):
        calls.append(Call("send_email", {"to": m.group(1), "body": context}, origin))
    for m in POST.finditer(text):
        calls.append(Call("http_post", {"url": m.group(1), "body": context}, origin))
    if ALL.search(text):
        calls.append(Call("read_all_members", {}, origin))
    for m in OTHER.finditer(text):
        calls.append(Call("read_member", {"member_id": int(m.group(1))}, origin))
    for m in DELETE.finditer(text):
        calls.append(Call("delete_member", {"member_id": int(m.group(1))}, origin))
    return calls


def run(task: dict, record: str, authorize) -> list[dict]:
    """Returns the log of every tool call attempted, with the guard's verdict."""
    log = []
    steps = [Call("read_member", {"member_id": task["member_id"]}, "user")]
    steps += plan(task["user_request"], "user", record)
    for d in task.get("documents", []):
        steps += plan(d, "document", record)
    for c in steps:
        ok, why = authorize(c)
        log.append({"tool": c.tool, "args": c.args, "origin": c.origin, "allowed": ok, "reason": why})
    return log
