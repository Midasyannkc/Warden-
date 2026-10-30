"""Execute NHI remediation against IAM through boto3. In this repo the endpoint is moto,
an in-process AWS mock, so nothing touches a real account; the calls are the real API calls."""
from __future__ import annotations

import json


def provision(iam, inventory: dict) -> dict:
    """Create an IAM user, access key and inline policy for every AWS key identity."""
    keys = {}
    for i in inventory["identities"]:
        if i["system"] != "aws" or i["kind"] != "iam_user_key":
            continue
        iam.create_user(UserName=i["name"], Tags=[{"Key": "owner", "Value": i.get("owner") or "none"}])
        iam.put_user_policy(UserName=i["name"], PolicyName="inline", PolicyDocument=json.dumps({"Version": "2012-10-17", **i["policy"]}))
        keys[i["name"]] = iam.create_access_key(UserName=i["name"])["AccessKey"]["AccessKeyId"]
    return keys


def rotate_key(iam, user: str) -> dict:
    """Create the new key first, then deactivate and delete the old ones, so a consumer
    that picks up the new key never sees a gap."""
    old = [k["AccessKeyId"] for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]]
    new = iam.create_access_key(UserName=user)["AccessKey"]["AccessKeyId"]
    for k in old:
        iam.update_access_key(UserName=user, AccessKeyId=k, Status="Inactive")
        iam.delete_access_key(UserName=user, AccessKeyId=k)
    return {"action": "rotate", "user": user, "deleted": old, "created": new}


def disable_user(iam, user: str) -> dict:
    ids = [k["AccessKeyId"] for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]]
    for k in ids:
        iam.update_access_key(UserName=user, AccessKeyId=k, Status="Inactive")
    iam.tag_user(UserName=user, Tags=[{"Key": "warden", "Value": "disabled-orphaned-or-stale"}])
    return {"action": "disable", "user": user, "deactivated": ids}


def remediate(iam, issues: list[dict]) -> list[dict]:
    """Stale or orphaned keys are deactivated; keys that are merely old are rotated."""
    by_name: dict[str, set] = {}
    for i in issues:
        by_name.setdefault(i["name"], set()).add(i["rule"])
    existing = {u["UserName"] for u in iam.list_users()["Users"]}
    evidence = []
    for name, rules in sorted(by_name.items()):
        if name not in existing:
            continue
        if rules & {"stale", "orphaned"}:
            evidence.append(disable_user(iam, name))
        elif "old-credential" in rules:
            evidence.append(rotate_key(iam, name))
    return evidence
