import subprocess

import boto3
import pytest
from moto import mock_aws

from warden.sdlc import clawback

ENV = {"GIT_AUTHOR_NAME": "dana", "GIT_AUTHOR_EMAIL": "d@x.test", "GIT_COMMITTER_NAME": "dana", "GIT_COMMITTER_EMAIL": "d@x.test",
       "HOME": "/tmp", "PATH": "/usr/bin:/bin:/usr/local/bin"}


def sh(repo, *cmd, author=None):
    env = dict(ENV)
    if author:
        env["GIT_AUTHOR_NAME"] = author
    subprocess.run(cmd, cwd=repo, env=env, check=True, capture_output=True)


def commit(repo, name, text, msg, author=None):
    (repo / name).write_text(text)
    sh(repo, "git", "add", name)
    sh(repo, "git", "commit", "-q", "-m", msg, author=author)


@pytest.fixture
def repo(tmp_path):
    sh(tmp_path, "git", "init", "-q", "-b", "main")
    commit(tmp_path, "app.py", "def f():\n    return 1\n", "base")
    (tmp_path / "check.sh").write_text("#!/bin/sh\ngrep -q AKIA app.py && exit 1\nexit 0\n")
    sh(tmp_path, "git", "add", "check.sh")
    sh(tmp_path, "git", "commit", "-q", "-m", "add check")
    sh(tmp_path, "git", "tag", "base")
    return tmp_path


def make_iam():
    iam = boto3.client("iam", region_name="us-east-1")
    for u in ["ai-agent", "svc-db"]:
        iam.create_user(UserName=u)
        iam.create_access_key(UserName=u)
        iam.put_user_policy(UserName=u, PolicyName="p", PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}')
    return iam


@mock_aws
def test_clawback_reverts_ai_commits_and_leaves_human_work(repo):
    commit(repo, "app.py", "KEY='AKIAEXAMPLE'\ndef f():\n    return 1\n", "agent: add client\n\nCo-Authored-By: Claude <n@x.test>")
    commit(repo, "docs.md", "notes\n", "human docs")
    iam = make_iam()
    res = clawback.run(repo, "base", iam, "ai-agent", ["svc-db"], "sh check.sh")
    assert res["ok"]
    assert "AKIA" not in (repo / "app.py").read_text()
    assert (repo / "docs.md").exists()
    steps = [e["step"] for e in res["evidence"]]
    assert steps == ["revoke-agent", "revert", "rotate-exposed", "verify"]


@mock_aws
def test_agent_credentials_are_dead_after_clawback(repo):
    commit(repo, "app.py", "x=1\n", "agent change", author="devin-bot[bot]")
    iam = make_iam()
    clawback.run(repo, "base", iam, "ai-agent", [], "true")
    assert all(k["Status"] == "Inactive" for k in iam.list_access_keys(UserName="ai-agent")["AccessKeyMetadata"])
    assert iam.list_user_policies(UserName="ai-agent")["PolicyNames"] == []


@mock_aws
def test_main_branch_is_untouched(repo):
    commit(repo, "app.py", "x=1\n", "agent change\n\nClaude-Session: https://s.test/1")
    before = clawback.git(repo, "rev-parse", "main")
    clawback.run(repo, "base", make_iam(), "ai-agent", [], "true")
    assert clawback.git(repo, "rev-parse", "main") == before
