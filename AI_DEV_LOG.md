# AI development log

This project was built in one session with Claude as the coding assistant and Christian Kouadio Kouassi as the author and owner of every commit.

## What the assistant generated

- The Python source, the tests, the synthetic datasets and their generators (`scripts/build_corpus.py`, `scripts/build_events.py`), the seeded target app and Terraform, the README, the report generator and this log.
- The custom Semgrep rules, the CODEOWNERS file, the GitHub ruleset, the CI and CodeQL workflows, and the hardened Terraform.

## What was checked, and how

- **Real tools, real output.** Bandit, Semgrep, Checkov and detect-secrets were run on the code and their JSON parsed. The counts in the README come from `python -m warden`, not from memory.
- **Every incident has a failing test first.** Each reproduce commit was run and seen to fail for the stated reason before the fix was written. INC-1, INC-7, INC-15, INC-16 and INC-17 came from running real scanner output; INC-15 and INC-17 were found while building the baseline scan and were not planned.
- **Exploit tests for the app.** Each seeded vulnerability has a test that attacks the running Flask app through its test client (another member's id, an injection string, a YAML tag that calls a function, a shifted clock for token expiry).
- **Tests written wrongly at first.** The first conflict test for the clawback did not conflict (git merged the edits cleanly), so it was rewritten to change the same line before it could count as a reproduction. The first scan test asserted seeded flaws on the live tree and went red after remediation; it now scans the baseline commit.
- **Labelled data.** The CloudTrail events carry a hidden `_label` used only for scoring, written before the detection rules.
- **Dates.** KEV entries, due dates and ransomware flags were read from the downloaded catalog, not typed.

## What was not verified

- No live AWS, Okta, GitHub organization or CodeQL run. The GitHub ruleset and workflows are valid YAML and JSON and are checked by tests for internal consistency, not applied.
- CVSS scores in the synthetic SBOM were entered by hand from public advisories and should be re-checked before real use.
- The agent harness uses a deterministic obedient simulation. It says nothing about how a language model behaves. Provenance tagging (which text came from a document) is assumed to be available to the orchestrator; real systems have to build that.
- The HIPAA citations are to 45 CFR 164.312 and 164.308(a)(1)(ii)(A) as I know the current text; whether the 2025 proposed amendments were finalized was not confirmed and the map does not rely on them.
- Vendor dossiers describe fictional vendors.
- Warden is a demonstration of method, not a security product.
