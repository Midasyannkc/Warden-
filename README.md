# Warden

A security-as-code toolkit for a healthcare SaaS platform, written in Python. It is the kind of work a first dedicated security engineer does when there is no security team to hand things to: find what is wrong, rank it by real risk, fix the identity and secrets mess, keep AI-written code from approving itself, and keep an AI agent from leaking PHI.

The fictional company is CareLoop, a GI care platform with a member-facing API on AWS. The code under test is a small Flask API and Terraform that were seeded with the flaws a healthcare app really ships with.

## Results

Everything below is computed by `python -m warden` and written to [docs/REPORT.md](docs/REPORT.md) and `out/report.json`.

| Area | Before | After |
| --- | --- | --- |
| Unique findings from Bandit, Semgrep, Checkov, detect-secrets (61 raw) | 39 (20 high) | 8 (0 high) |
| Non-human identity issues (11 identities) | 16 | 9 (the rest need an owner decision) |
| Prompt injection attacks that succeed against the agent (22 attacks) | 100% | 0% with all controls |
| Legitimate agent requests that need a human click | 0 of 10 | 2 of 10 |
| Detection rules on 486 synthetic CloudTrail events | not applicable | 11 rules, precision 100%, recall 100% |
| Pull request scenarios where the AI would approve its own code | allowed | denied (6 scenarios) |
| Vulnerable components in CISA's KEV catalog | 6 of 7 | 7-day clock for all six |

## How it maps to the work

| What a security engineer owns | Where it is |
| --- | --- |
| Application security: threat modeling, secure code review for access control and secrets | `target/app`, exploit tests in `tests/test_target_app.py`, custom Semgrep rules in `semgrep_rules/` |
| Secure SDLC tooling: SAST, secret scanning, IaC scanning, dependency risk | `warden/scan`, `warden/vulns`, `.github/workflows/codeql.yml` |
| Agentic SDLC: phase gates, AI never its own gate, tested clawback | `warden/sdlc` (gate, CODEOWNERS, Ed25519 attestation, clawback) |
| Non-human identity and secrets | `warden/nhi` (inventory, analyzer, rotation through boto3 on moto) |
| AWS: IAM, network, logging, encryption | `target/infra/main.tf` before and after, Checkov results |
| GitHub controls: branch protection, CODEOWNERS, push protection | `.github/` (ruleset, CODEOWNERS, secret scanning config), `scripts/apply_github_controls.sh` |
| AI and vendor review before PHI | `warden/vendors` and `warden/agents` |
| Vulnerability management and feedback into development | `warden/vulns` (KEV priority, SLA clocks, recurring classes to guardrails) |
| HIPAA Security Rule technical safeguards, detection and response | `warden/compliance`, `warden/detect` |
| Explaining a tradeoff to engineers and executives | `docs/REPORT.md` has an executive section and an engineering section; vendor output is written for both |

## How it works

```
target app + Terraform ──> Bandit, Semgrep, Checkov, detect-secrets ──> one Finding model
                                                                          │
              dedupe by fingerprint ─ CISA KEV and exposure priority ─ SLA clocks ─ recurring classes become guardrails
NHI inventory ──> stale, orphaned, wildcard, escalation, over-scoped ──> rotate or disable through IAM (moto)
pull request ──> AI authored? ──> independent human + code owner + signed CI attestation ──> allow or deny ──> clawback if risk spikes
agent tool call ──> scope ──> egress allowlist ──> PHI DLP ──> provenance gate (untrusted content cannot trigger actions)
vendor dossier ──> every claim checked against evidence ──> verdict for executives, checklist for engineers
CloudTrail events ──> 11 rules with ATT&CK ids ──> scored against labelled events
everything ──> HIPAA 164.312 map: a gap with its findings, or "no open findings", never "compliant"
```

Design notes are in [docs/architecture.md](docs/architecture.md).

## Incidents

Seventeen defects were found and fixed. Each has a commit that adds a failing test (run and seen to fail for the right reason) followed by a separate fix commit. Details are in [docs/incidents.md](docs/incidents.md).

Two kinds are mixed on purpose and the log says which is which. INC-8 to INC-14 are the vulnerabilities seeded in the target app and Terraform, found by exploit tests and by the real scanners. The rest are defects in Warden itself, found by tests, the labelled data, or by running the real tools: a custom Semgrep rule that silently matched nothing, a secret scanner that prints nothing outside a git tree, and a CODEOWNERS file whose last line disabled every rule above it.

This is a construction method, not a record of accidental bugs: the first draft of each module used the simple assumption most implementations start with (a string suffix for a domain, a window that stops at its threshold, a regex for the dashed SSN), and the incidents record what tests, labelled data and the real tools did to those assumptions. INC-15 and INC-17 were not planned; they surfaced when the real tools were run from a scratch checkout and against the baseline.

<!-- incidents:start -->
| # | Incident | Found by | Reproduce | Fix |
| --- | --- | --- | --- | --- |
| INC-1 | One hardcoded secret reported by two scanners counted twice | vulnerability-management test on real scanner output | `a69f003` | `9e2bcb8` |
| INC-2 | Catch-all CODEOWNERS rule listed last disabled every security-owner rule | SDLC gate tests | `b845f62` | `fe74951` |
| INC-3 | Clawback crashed on a revert conflict and skipped credential rotation | clawback drill test with a later human edit | `6476e5f` | `af9602d` |
| INC-4 | Lookalike recipient domains passed the internal-domain check and skipped DLP | prompt injection harness | `742828e` | `c3ab391` |
| INC-5 | PHI written as 'Social 123 45 6789' or 'medical record number' slipped past DLP | prompt injection harness, vendor egress case | `a99b8cc` | `271aea7` |
| INC-6 | Burst alerts stopped at the threshold and undercounted PHI objects read | detection scoring against labelled events | `fe7f181` | `ac87339` |
| INC-7 | Scanner categories with no control mapping made controls look clean | control-map test against real scans | `fcb45a1` | `c9849aa` |
| INC-8 | Any signed-in member could read any other member's record and messages (BOLA) | exploit test (no scanner flagged it until INC-17) | `c0895ee` | `380e17b` |
| INC-9 | SQL injection in member search, and directory search open to every member | exploit test, Bandit B608, custom Semgrep rule | `a733b42` | `cbe42f3` |
| INC-10 | Export endpoint had no role check and a debug endpoint dumped the environment | exploit test (no scanner flagged it until INC-17) | `b2850d1` | `da996be` |
| INC-11 | YAML import could construct Python objects and the vendor call skipped TLS verification | Bandit B506 and B501, exploit test | `f583192` | `1a068ca` |
| INC-12 | Credentials committed in source and passwords stored as unsalted MD5 | detect-secrets, Bandit B105 and B324 | `430d7a4` | `bd68f20` |
| INC-13 | Tokens never expired and the signature was compared with != | code review, exploit test with a shifted clock | `3552809` | `0d4b036` |
| INC-14 | Terraform exposed PHI storage, the database and the cluster and granted Action * on * | Checkov (44 failed checks) | `748b418` | `3e4b980` |
| INC-15 | The secret scanner silently found nothing outside a git work tree | baseline scan from a scratch checkout | `91c2251` | `645e0e6` |
| INC-16 | Secret scanner flagged a Terraform boolean as a credential | remediated-tree scan | `825ca37` | `6151e9c` |
| INC-17 | The custom Semgrep rule for BOLA never matched anything | coverage test over the vulnerable baseline | `41cc5cf` | `41d1b1a` |
<!-- incidents:end -->

## Run it

```
pip install -r requirements.txt --break-system-packages
python3 -m pytest -q        # 105 tests, about 7 seconds once scanner output is cached
python3 -m warden           # runs every module and writes out/report.json and docs/REPORT.md
make rescan                 # force the real scanners to run again (about 100 seconds per tree)
```

The first run of the tests or the report runs the four real scanners twice (the vulnerable baseline and the current tree). Raw output is cached under `out/` by a hash of the scanned files and of how the tools are invoked.

## What is real and what is not

Real: the CISA KEV catalog (version 2026.10.29, 1,764 entries, hash in `data/SOURCE.md`); Bandit, Semgrep, Checkov and detect-secrets running on the code in this repo; boto3 calls against moto for rotation, disabling and clawback; git operations in temporary repositories; Ed25519 signatures; the CODEOWNERS and ruleset formats GitHub uses.

Synthetic and disclosed: the CareLoop app and its Terraform, the SBOM pairings (real CVEs, author-entered CVSS), the NHI inventory and HR roster, the CloudTrail events (real field names, invented activity), the vendor dossiers, the injection corpus and the scan history behind the recurring-issue feedback.

Not done here, so not claimed: no live AWS account, Okta, or GitHub organization (the ruleset and workflows are config as code that has not been applied); CodeQL was not run (it is written as a workflow and cannot be installed in this environment); the Semgrep registry and OSV were not reachable, so Semgrep uses local rules and there is no dependency audit beyond the KEV match; the agent is a deterministic simulation that obeys everything, not a language model, so the injection numbers measure the controls and say nothing about how any model behaves; the HIPAA map covers technical safeguards only and the 2025 proposal to make encryption and MFA mandatory was not treated as final; this is not a substitute for a penetration test, a risk analysis, or a compliance audit.
