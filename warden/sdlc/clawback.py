"""Clawback: the tested procedure for pulling AI-written changes back out when risk spikes.

Steps, in order: cut the agent's access, revert its commits on a separate branch (never on
the protected branch), rotate any credential the agent could have seen, run the repo's
checks, and write evidence of each step."""
from __future__ import annotations

import subprocess

from ..nhi import rotate
from . import gate


def git(repo, *args, check=True):
    p = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout.strip()


def ai_commits(repo, base, policy=None):
    policy = policy or gate.load_policy()
    out = []
    for sha in git(repo, "rev-list", f"{base}..HEAD").splitlines():
        author = git(repo, "log", "-1", "--format=%an", sha)
        body = git(repo, "log", "-1", "--format=%B", sha)
        c = {"author": author, "trailers": gate.trailers_from_message(body)}
        if gate.is_ai_commit(c, policy):
            out.append(sha)
    return out  # newest first


def revoke_agent(iam, agent_user):
    keys = [k["AccessKeyId"] for k in iam.list_access_keys(UserName=agent_user)["AccessKeyMetadata"]]
    for k in keys:
        iam.update_access_key(UserName=agent_user, AccessKeyId=k, Status="Inactive")
    for pol in iam.list_user_policies(UserName=agent_user)["PolicyNames"]:
        iam.delete_user_policy(UserName=agent_user, PolicyName=pol)
    return {"step": "revoke-agent", "user": agent_user, "deactivated": keys}


def run(repo, base, iam, agent_user, exposed_users, check_cmd, branch="clawback/drill"):
    evidence = []
    evidence.append(revoke_agent(iam, agent_user))
    shas = ai_commits(repo, base)
    git(repo, "checkout", "-q", "-b", branch)
    reverted, conflicts = [], []
    for sha in shas:
        p = subprocess.run(["git", "revert", "--no-edit", sha], cwd=repo, capture_output=True, text=True)
        if p.returncode:
            # A later edit touched the same lines. Leave the tree clean and report it for a human;
            # the rest of the procedure (credential rotation above all) must still run.
            git(repo, "revert", "--abort", check=False)
            conflicts.append(sha)
        else:
            reverted.append(sha)
    evidence.append({"step": "revert", "branch": branch, "reverted": reverted, "conflicts": conflicts})
    for u in exposed_users:
        evidence.append({"step": "rotate-exposed", **rotate.rotate_key(iam, u)})
    p = subprocess.run(check_cmd, cwd=repo, shell=True, capture_output=True, text=True)
    evidence.append({"step": "verify", "cmd": check_cmd, "passed": p.returncode == 0})
    return {"ok": p.returncode == 0 and not conflicts, "evidence": evidence}
