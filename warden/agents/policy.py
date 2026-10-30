"""Authorization for AI agent tool calls: least-privilege scopes, egress allowlists, DLP, and
provenance gating (an action planned from untrusted content never runs unattended)."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import dlp

STATE_CHANGING = {"send_email", "http_post", "delete_member"}


@dataclass
class Grant:
    agent: str
    scopes: set = field(default_factory=set)       # e.g. {"member:read:self", "email:send:internal"}
    email_domains: tuple = ()
    egress_hosts: tuple = ()


@dataclass
class Call:
    tool: str
    args: dict
    origin: str = "user"   # "user" or "document": where the planning text came from


def is_internal(address: str, domains: tuple) -> bool:
    """True only when the part after the last @ is exactly an internal domain or a subdomain of one."""
    host = address.rpartition("@")[2].lower()
    return any(host == d or host.endswith("." + d) for d in domains)


SUMMARIZER = Grant("support-summarizer", {"member:read:self", "email:send:internal"}, ("careloop.test",), ())


def authorize(call: Call, grant: Grant, session_member: int, *, layers=("authz", "egress", "dlp", "provenance")) -> tuple[bool, str]:
    t, a = call.tool, call.args
    if "authz" in layers:
        if t == "read_member":
            if "member:read:self" not in grant.scopes:
                return False, "scope member:read:self not granted"
            if a.get("member_id") != session_member:
                return False, "member id does not match the session member"
        elif t == "read_all_members":
            return False, "scope member:read:all not granted"
        elif t == "delete_member":
            return False, "scope member:delete not granted"
        elif t == "send_email":
            if "email:send:internal" not in grant.scopes:
                return False, "scope email:send:internal not granted"
        elif t == "http_post":
            if not grant.egress_hosts:
                return False, "no egress hosts granted"
        else:
            return False, f"unknown tool {t}"
    if "egress" in layers:
        if t == "send_email" and not is_internal(a.get("to", ""), grant.email_domains):
            return False, "recipient outside the internal domain"
        if t == "http_post" and urlparse(a.get("url", "")).hostname not in grant.egress_hosts:
            return False, "host not on the egress allowlist"
    if "dlp" in layers and t in {"send_email", "http_post"}:
        external = t == "http_post" or not is_internal(a.get("to", ""), grant.email_domains)
        hits = dlp.scan(str(a.get("body", "")))
        if hits and external:
            return False, "PHI in outbound content: " + ",".join(hits)
    if "provenance" in layers and call.origin == "document" and t in STATE_CHANGING:
        return False, "state-changing action planned from untrusted content needs human confirmation"
    return True, "ok"

# A grant for a summarizer wired to a vendor LLM gateway. The host is allowed; PHI must still not leave.
VENDOR_SUMMARIZER = Grant("vendor-summarizer", {"member:read:self", "email:send:internal", "http:post:vendor"},
                          ("careloop.test",), ("api.vendor-llm.test",))
GRANTS = {"default": SUMMARIZER, "vendor": VENDOR_SUMMARIZER}
