# Architecture

Warden is a set of small modules that share one finding model. Each box is a package with tests.

```
target/ (CareLoop API + Terraform)
   │  real scanners: Bandit, Semgrep (local rules), Checkov, detect-secrets
   ▼
warden/scan ──> Finding ──> warden/vulns ──> dedupe, CISA KEV priority, SLA, recurring-issue feedback
                                │
data/nhi_inventory.json ──> warden/nhi ──> analyze ──> remediate through boto3 (moto)
.github/CODEOWNERS ───────> warden/sdlc ──> gate (phase gates, CODEOWNERS, signed attestation) ──> clawback
data/injection_corpus.json ─> warden/agents ──> scopes, egress, DLP, provenance gate ──> measured harness
data/vendor_dossiers.json ─> warden/vendors ──> claim vs evidence ──> two-audience output
data/cloudtrail_events.json ─> warden/detect ──> rules with ATT&CK ids ──> precision and recall
                                │
                                ▼
                        warden/compliance ──> HIPAA 164.312 map (gap or "no open findings")
                                │
                                ▼
                     python -m warden ──> out/report.json, docs/REPORT.md
```

## Design choices

- **Real tools, normalized once.** Every scanner is turned into the same `Finding` (tool, rule, severity, category, file, resource). A fingerprint built from category, file and resource lets the same weakness reported by two tools collapse into one finding, and ignores line numbers so a moved line does not reopen a closed finding.
- **KEV before CVSS.** A vulnerable component that CISA lists as known exploited gets a 7 day clock whatever its score. OpenSSL 1.0.1f (CVSS 7.5) is due before a 7.2 library that is not in the catalog.
- **AI is never its own gate.** The gate treats a commit as AI authored if its author matches a bot or agent pattern or it carries an AI trailer. An AI authored or sensitive change needs an approval from a human who did not write it, a code owner approval for sensitive paths, and an Ed25519 attestation of the CI checks signed by a key in a separate keyring and bound to the head commit. The agent's own key is not in that keyring.
- **Clawback is a procedure with evidence.** Cut access first, then revert on a separate branch, then rotate anything the agent could have seen, then run the checks. A revert conflict is reported to a human and never stops the rest.
- **Controls around the agent, not trust in it.** The injection harness uses a deliberately obedient simulated agent so the numbers measure the controls. Layers are measured one at a time so each one has to earn its place.
- **Compliance claims stay small.** A control is a gap with the findings behind it, or "no open findings from technical checks". Warden never writes "compliant".
