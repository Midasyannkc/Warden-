import boto3
from moto import mock_aws

from warden.nhi import analyze as A, rotate as R

INV = A.load("nhi_inventory.json")
ROSTER = A.load("hr_roster.json")


def setup():
    iam = boto3.client("iam", region_name="us-east-1")
    return iam, R.provision(iam, INV)


@mock_aws
def test_provision_creates_a_user_per_aws_key():
    iam, keys = setup()
    assert set(keys) == {"svc-report-batch", "svc-legacy-etl", "svc-ci-deployer", "svc-analytics-export"}


@mock_aws
def test_rotation_replaces_the_key_with_no_gap():
    iam, keys = setup()
    ev = R.rotate_key(iam, "svc-ci-deployer")
    now = [k["AccessKeyId"] for k in iam.list_access_keys(UserName="svc-ci-deployer")["AccessKeyMetadata"]]
    assert now == [ev["created"]] and keys["svc-ci-deployer"] in ev["deleted"]


@mock_aws
def test_remediate_disables_orphaned_and_stale_keys_only():
    iam, keys = setup()
    ev = R.remediate(iam, A.analyze_all(INV, ROSTER))
    disabled = {e["user"] for e in ev if e["action"] == "disable"}
    assert disabled == {"svc-legacy-etl", "svc-analytics-export"}
    meta = iam.list_access_keys(UserName="svc-legacy-etl")["AccessKeyMetadata"]
    assert all(k["Status"] == "Inactive" for k in meta)
    healthy = iam.list_access_keys(UserName="svc-report-batch")["AccessKeyMetadata"]
    assert all(k["Status"] == "Active" for k in healthy)
