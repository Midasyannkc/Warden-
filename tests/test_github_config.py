import json
import os

import yaml


def test_workflows_are_valid_yaml_with_least_privilege():
    for name in ["ci.yml", "codeql.yml"]:
        wf = yaml.safe_load(open(f".github/workflows/{name}"))
        assert wf["permissions"]["contents"] == "read"
        assert all(not str(step.get("uses", "")).endswith("@main") for job in wf["jobs"].values() for step in job["steps"])


def test_ruleset_requires_code_owner_review_and_blocks_force_push():
    rs = json.load(open(".github/rulesets/main-protection.json"))
    kinds = {r["type"] for r in rs["rules"]}
    assert {"non_fast_forward", "deletion", "required_signatures", "pull_request", "required_status_checks"} <= kinds
    pr = next(r for r in rs["rules"] if r["type"] == "pull_request")["parameters"]
    assert pr["require_code_owner_review"] and pr["require_last_push_approval"] and pr["dismiss_stale_reviews_on_push"]
    assert rs["bypass_actors"] == []


def test_required_checks_exist_as_jobs():
    rs = json.load(open(".github/rulesets/main-protection.json"))
    needed = {c["context"] for r in rs["rules"] if r["type"] == "required_status_checks" for c in r["parameters"]["required_status_checks"]}
    jobs = set()
    for name in ["ci.yml", "codeql.yml"]:
        jobs |= set(yaml.safe_load(open(f".github/workflows/{name}"))["jobs"])
    assert needed <= jobs


def test_secret_scanning_exclusions_are_only_fixtures():
    cfg = yaml.safe_load(open(".github/secret_scanning.yml"))
    assert set(cfg["paths-ignore"]) == {"data/**", "tests/**"}
