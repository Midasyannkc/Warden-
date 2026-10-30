# Data sources and disclosed substitutions

## Real data

| File | Source | Notes |
| --- | --- | --- |
| data/raw/kev.json | CISA Known Exploited Vulnerabilities catalog, https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json | Unmodified. Catalog version 2026.10.29, 1,764 entries. |

## Real tools, run for real

Bandit, Semgrep (with local rules in semgrep_rules/, because the Semgrep registry was not reachable), Checkov (on Terraform HCL, no terraform binary needed) and detect-secrets scan the target app and Terraform in this repo. AWS behavior runs against moto, an in-process AWS mock, through boto3.

## Disclosed synthetic data

The target "CareLoop" member API, its Terraform, the non-human identity inventory, the sample CloudTrail events, the vendor dossiers, the prompt injection corpus and the git histories used by the SDLC gate tests are all invented. The AWS access key in target/app/config.py is the example key printed in AWS documentation. No real credentials, member data or vendor claims are used.

## Not done

No live AWS account, no CodeQL (not installable here), no Okta, no live LLM or agent. The agent security harness uses a deterministic simulated agent.
