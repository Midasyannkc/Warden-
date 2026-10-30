"""Generate data/cloudtrail_events.json: synthetic events in the real CloudTrail record
shape, a noisy benign baseline plus planted attack sequences. Each event carries a hidden
_label used only to score the detections."""
import datetime as dt
import json
import os
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rnd = random.Random(7)
T0 = dt.datetime(2026, 10, 27, 8, 0, 0)
events = []
n = [0]


def ev(minutes, name, source, user, *, utype="IAMUser", ip="198.51.100.10", params=None, resp=None, extra=None, err=None, label=None):
    n[0] += 1
    t = T0 + dt.timedelta(minutes=minutes, seconds=rnd.randint(0, 40))
    e = {"eventID": f"evt-{n[0]:05d}", "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": source, "eventName": name,
         "awsRegion": "us-east-1", "sourceIPAddress": ip,
         "userIdentity": {"type": utype, "userName": user, "arn": f"arn:aws:iam::111122223333:{'root' if utype == 'Root' else 'user/' + user}"},
         "requestParameters": params, "responseElements": resp, "additionalEventData": extra, "_label": label}
    if err:
        e["errorCode"] = err
    events.append(e)


users = ["priya", "marcus", "lena", "omar", "sofia", "svc-ci-deployer", "svc-report-batch"]
# benign baseline
for m in range(0, 2800, 7):
    u = rnd.choice(users)
    k = rnd.random()
    if k < 0.35:
        ev(m, "GetObject", "s3.amazonaws.com", u, params={"bucketName": "careloop-reports", "key": f"r/{m}.csv"})
    elif k < 0.55:
        ev(m, "ConsoleLogin", "signin.amazonaws.com", u, resp={"ConsoleLogin": "Success"}, extra={"MFAUsed": "Yes"})
    elif k < 0.70:
        ev(m, "DescribeInstances", "ec2.amazonaws.com", u)
    elif k < 0.80:
        ev(m, "PutObject", "s3.amazonaws.com", u, params={"bucketName": "careloop-reports", "key": f"w/{m}.csv"})
    elif k < 0.88:
        ev(m, "AssumeRole", "sts.amazonaws.com", u, params={"roleArn": "arn:aws:iam::111122223333:role/app-runtime-role"})
    elif k < 0.94:
        ev(m, "CreateAccessKey", "iam.amazonaws.com", u, params={"userName": u})  # rotating your own key is normal
    else:
        ev(m, "GetObject", "s3.amazonaws.com", u, params={"bucketName": "careloop-reports", "key": "x"}, err="AccessDenied")
# planted attacks
ev(300, "ConsoleLogin", "signin.amazonaws.com", "root", utype="Root", ip="203.0.113.50", resp={"ConsoleLogin": "Success"}, extra={"MFAUsed": "No"}, label="root-login")
ev(420, "ConsoleLogin", "signin.amazonaws.com", "marcus", ip="203.0.113.77", resp={"ConsoleLogin": "Success"}, extra={"MFAUsed": "No"}, label="console-no-mfa")
ev(500, "CreateAccessKey", "iam.amazonaws.com", "lena", params={"userName": "svc-legacy-etl"}, label="key-for-other-user")
ev(502, "AttachUserPolicy", "iam.amazonaws.com", "lena", params={"userName": "lena", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, label="admin-policy")
ev(700, "PutBucketAcl", "s3.amazonaws.com", "omar", params={"bucketName": "careloop-member-documents", "AccessControlList": {"Grant": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}}, label="public-bucket")
ev(702, "PutBucketPolicy", "s3.amazonaws.com", "omar", params={"bucketName": "careloop-audit-logs", "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\"}]}"}, label="public-bucket")
ev(900, "StopLogging", "cloudtrail.amazonaws.com", "omar", params={"name": "main-trail"}, label="logging-disabled")
ev(905, "DeleteTrail", "cloudtrail.amazonaws.com", "omar", params={"name": "main-trail"}, label="logging-disabled")
ev(1100, "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", "sofia", params={"groupId": "sg-0abc", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}, label="open-ssh")
ev(1150, "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", "sofia", params={"groupId": "sg-0abc", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})  # public HTTPS is expected
ev(1300, "UpdateAssumeRolePolicy", "iam.amazonaws.com", "marcus", params={"roleName": "app-runtime-role", "policyDocument": "{\"Statement\":[{\"Principal\":{\"AWS\":\"*\"}}]}"}, label="trust-policy-open")
ev(1500, "DeleteDetector", "guardduty.amazonaws.com", "omar", params={"detectorId": "d-1"}, label="detection-disabled")
for i in range(60):   # exfil burst from a PHI bucket
    ev(1700 + i * 0.05, "GetObject", "s3.amazonaws.com", "svc-report-batch", ip="192.0.2.99", params={"bucketName": "careloop-phi-exports", "key": f"chart-{i}.json"}, label="bulk-phi-read")
for i in range(14):   # recon: many AccessDenied from one principal
    ev(2000 + i * 0.3, ["ListUsers", "ListRoles", "ListBuckets", "GetAccountAuthorizationDetails"][i % 4], "iam.amazonaws.com", "svc-ci-deployer", ip="192.0.2.45", err="AccessDenied", label="access-denied-burst")
events.sort(key=lambda e: e["eventTime"])
json.dump({"_note": "Synthetic CloudTrail-shaped events (real field names, invented activity). _label is ground truth for scoring only.", "events": events},
          open(os.path.join(ROOT, "data/cloudtrail_events.json"), "w"))
print(len(events), "events;", sum(1 for e in events if e["_label"]), "labelled")
