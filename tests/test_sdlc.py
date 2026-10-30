import copy
import pytest

from warden.sdlc import attest, codeowners, gate

POLICY = gate.load_policy()
RULES = codeowners.parse(open(gate.ROOT + "/.github/CODEOWNERS").read())
CI_PRIV, CI_PUB = attest.new_keypair()
AGENT_PRIV, AGENT_PUB = attest.new_keypair()
KEYRING = {"ci-1": CI_PUB}


def pr(files=("README.md",), author="dana", trailers=None, approvals=None, head="abc123", checks=None, sign_with=("ci-1", CI_PRIV), **kw):
    payload = {"head": head, "checks": checks or {"sast": "pass", "secrets": "pass", "iac": "pass"}}
    base = {
        "head": head,
        "commits": [{"author": author, "trailers": trailers or {}, "files": list(files)}],
        "approvals": approvals if approvals is not None else [{"user": "erin", "member_of": ["@careloop/engineering"]}],
        "tests_pass": True,
        "attestation": attest.sign(sign_with[1], sign_with[0], payload),
        "findings": [],
    }
    base.update(kw)
    return base


def run(p):
    return gate.evaluate(p, POLICY, RULES, KEYRING)


AI = {"Co-Authored-By": "Claude Sonnet <noreply@anthropic.com>"}


def test_plain_human_change_with_one_approval_is_allowed():
    assert run(pr())["allow"]


def test_ai_trailer_marks_commit_as_ai_authored():
    assert gate.is_ai_commit({"author": "dana", "trailers": AI}, POLICY)
    assert gate.is_ai_commit({"author": "dependabot[bot]", "trailers": {}}, POLICY)
    assert not gate.is_ai_commit({"author": "dana", "trailers": {"Co-Authored-By": "Sam <sam@x.test>"}}, POLICY)


def test_ai_change_approved_only_by_its_own_author_is_denied():
    p = pr(trailers=AI, approvals=[{"user": "dana", "member_of": []}])
    r = run(p)
    assert not r["allow"] and any("independent human" in x for x in r["reasons"])


def test_ai_agent_cannot_approve_its_own_change():
    p = pr(author="claude-agent", approvals=[{"user": "claude-agent", "member_of": []}, {"user": "review-bot[bot]", "member_of": []}])
    assert not run(p)["allow"]


def test_ai_change_with_independent_human_and_valid_attestation_is_allowed():
    assert run(pr(trailers=AI))["allow"]


def test_attestation_signed_by_unknown_key_is_rejected():
    p = pr(trailers=AI, sign_with=("agent-key", AGENT_PRIV))
    r = run(p)
    assert not r["allow"] and any("attestation" in x for x in r["reasons"])


def test_attestation_for_a_different_head_is_rejected():
    p = pr(trailers=AI)
    p["head"] = "def456"
    assert not run(p)["allow"]


def test_tampered_attestation_payload_is_rejected():
    p = pr(trailers=AI, checks={"sast": "fail", "secrets": "pass", "iac": "pass"})
    p["attestation"]["payload"]["checks"]["sast"] = "pass"
    assert not run(p)["allow"]


def test_failing_required_check_blocks_even_with_valid_signature():
    p = pr(trailers=AI, checks={"sast": "pass", "secrets": "fail", "iac": "pass"})
    r = run(p)
    assert not r["allow"] and any("secrets" in x for x in r["reasons"])


def test_open_critical_finding_blocks_release():
    p = pr(findings=[{"severity": "critical"}])
    assert not run(p)["allow"]


def test_trailer_parser_reads_message_footer():
    msg = "Fix thing\n\nBody text.\n\nCo-Authored-By: Claude <x@y.test>\nClaude-Session: https://example.test/s"
    t = gate.trailers_from_message(msg)
    assert t["Co-Authored-By"].startswith("Claude") and "Claude-Session" in t



def test_sensitive_path_needs_codeowner_approval():
    p = pr(files=("warden/sdlc/gate.py",), threat_model="TM-14")
    assert not run(p)["allow"]
    p["approvals"] = [{"user": "erin", "member_of": ["@careloop/security"]}]
    assert run(p)["allow"]


def test_sensitive_path_needs_threat_model():
    p = pr(files=("target/infra/main.tf",), approvals=[{"user": "sec", "member_of": ["@careloop/security"]}])
    r = run(p)
    assert not r["allow"] and any("threat model" in x for x in r["reasons"])


def test_codeowners_last_match_wins():
    assert codeowners.owners_for(RULES, "warden/sdlc/gate.py") == ["@careloop/security"]
    assert codeowners.owners_for(RULES, "README.md") == ["@careloop/engineering"]
    assert codeowners.owners_for(RULES, "target/app/config.py") == ["@careloop/security"]
    assert codeowners.owners_for(RULES, "target/app/auth_service.py") == ["@careloop/security"]
    assert codeowners.owners_for(RULES, ".github/workflows/ci.yml") == ["@careloop/security"]


def test_repo_codeowners_has_no_shadowed_rules():
    assert codeowners.lint(RULES) == []


def test_lint_catches_catch_all_listed_last():
    bad = codeowners.parse("/warden/sdlc/ @sec\n* @eng\n")
    assert codeowners.lint(bad) == ["/warden/sdlc/ is shadowed by the later catch-all *"]
