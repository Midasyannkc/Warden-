"""Six pull-request scenarios run through the gate, and a clawback drill, for the report."""
from __future__ import annotations

import os
import subprocess
import tempfile

import boto3
from moto import mock_aws

from . import attest, clawback, codeowners, gate

AI = {"Co-Authored-By": "Claude Sonnet <noreply@anthropic.com>"}


def _pr(files, author="dana", trailers=None, approvals=None, head="abc123", checks=None, key=None, **kw):
    ci_priv, ci_pub = KEYS["ci"]
    priv, kid = key or (ci_priv, "ci-1")
    payload = {"head": head, "checks": checks or {"sast": "pass", "secrets": "pass", "iac": "pass"}}
    pr = {"head": head, "commits": [{"author": author, "trailers": trailers or {}, "files": list(files)}],
          "approvals": approvals if approvals is not None else [{"user": "erin", "member_of": ["@careloop/engineering"]}],
          "tests_pass": True, "attestation": attest.sign(priv, kid, payload), "findings": []}
    pr.update(kw)
    return pr


KEYS = {"ci": attest.new_keypair(), "agent": attest.new_keypair()}


def run_scenarios():
    policy = gate.load_policy()
    rules = codeowners.parse(open(os.path.join(gate.ROOT, ".github/CODEOWNERS")).read())
    keyring = {"ci-1": KEYS["ci"][1]}
    sec = [{"user": "sam", "member_of": ["@careloop/security"]}]
    cases = [
        ("S1 human docs change, one approval", _pr(["README.md"])),
        ("S2 AI change approved only by its own submitter", _pr(["README.md"], trailers=AI, approvals=[{"user": "dana", "member_of": []}])),
        ("S3 AI change to the gate itself, engineer approval only", _pr(["warden/sdlc/gate.py"], trailers=AI, threat_model="TM-14")),
        ("S4 AI change, independent code owner, valid CI attestation", _pr(["warden/sdlc/gate.py"], trailers=AI, threat_model="TM-14", approvals=sec)),
        ("S5 AI change with an attestation signed by the agent's own key", _pr(["README.md"], trailers=AI, key=(KEYS["agent"][0], "agent-key"))),
        ("S6 AI change, valid signature, secrets check failing", _pr(["README.md"], trailers=AI, checks={"sast": "pass", "secrets": "fail", "iac": "pass"})),
    ]
    return [{"scenario": name, **gate.evaluate(pr, policy, rules, keyring)} for name, pr in cases]


def _git(repo, *a, author=None):
    env = {"GIT_AUTHOR_NAME": author or "dana", "GIT_AUTHOR_EMAIL": "d@x.test", "GIT_COMMITTER_NAME": "dana",
           "GIT_COMMITTER_EMAIL": "d@x.test", "HOME": "/tmp", "PATH": os.environ["PATH"]}
    subprocess.run(["git", *a], cwd=repo, env=env, check=True, capture_output=True)


@mock_aws
def run_clawback_drill():
    iam = boto3.client("iam", region_name="us-east-1")
    for u in ["ai-agent", "svc-db"]:
        iam.create_user(UserName=u)
        iam.create_access_key(UserName=u)
        iam.put_user_policy(UserName=u, PolicyName="p", PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}')
    with tempfile.TemporaryDirectory() as repo:
        _git(repo, "init", "-q", "-b", "main")
        open(os.path.join(repo, "app.py"), "w").write("def f():\n    return 1\n")
        open(os.path.join(repo, "check.sh"), "w").write("grep -q AKIA app.py && exit 1\nexit 0\n")
        _git(repo, "add", "."); _git(repo, "commit", "-q", "-m", "base"); _git(repo, "tag", "base")
        open(os.path.join(repo, "app.py"), "w").write("KEY='AKIAEXAMPLE'\ndef f():\n    return 1\n")
        _git(repo, "commit", "-qam", "agent: add client\n\nCo-Authored-By: Claude <n@x.test>")
        open(os.path.join(repo, "docs.md"), "w").write("notes\n")
        _git(repo, "add", "."); _git(repo, "commit", "-q", "-m", "human docs")
        result = clawback.run(repo, "base", iam, "ai-agent", ["svc-db"], "sh check.sh")
        result["human_work_kept"] = os.path.exists(os.path.join(repo, "docs.md"))
    return result
