# Incident log

Every incident has two commits. The first adds a test that fails for the right reason; a later one fixes the code and the same test passes. Hashes below come from `git log`.

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
| INC-18 | Report ordering changed between runs | clean clone verification | `3fbebe7` | `f3ac3fe` |
| INC-19 | The committed report was different on every run | clean clone verification, diffing two runs | `0e3807f` | `04c9b09` |

### INC-1: One hardcoded secret reported by two scanners counted twice

Bandit and detect-secrets both flagged the same credential but with different rule names and hashes, so dedupe kept both and the secret count was inflated (6 findings for 4 real locations). A secret is now identified by file and line, which the tools agree on.

Reproduce `a69f003`, fix `9e2bcb8`. Found by: vulnerability-management test on real scanner output.

### INC-2: Catch-all CODEOWNERS rule listed last disabled every security-owner rule

GitHub applies the last matching CODEOWNERS pattern, so a `*` rule at the bottom reassigned every path, including the gate itself and the Terraform, to the general engineering team. The file is reordered and a lint now reports any rule shadowed by a later catch-all.

Reproduce `b845f62`, fix `fe74951`. Found by: SDLC gate tests.

### INC-3: Clawback crashed on a revert conflict and skipped credential rotation

When a human had edited the same lines after the AI commit, git revert failed, the procedure raised, and the exposed keys were never rotated. A conflicted revert is now aborted cleanly, reported as a conflict for a human, and every other step still runs.

Reproduce `6476e5f`, fix `af9602d`. Found by: clawback drill test with a later human edit.

### INC-4: Lookalike recipient domains passed the internal-domain check and skipped DLP

The recipient check used a string suffix, so `hr@notcareloop.test` counted as internal, and because internal mail skips DLP the PHI left unscanned. The domain after the last @ is now matched exactly or as a true subdomain.

Reproduce `742828e`, fix `c3ab391`. Found by: prompt injection harness.

### INC-5: PHI written as 'Social 123 45 6789' or 'medical record number' slipped past DLP

The DLP patterns only matched dashed SSNs and the literal prefix MRN, so an allowlisted vendor host received a member's identifiers. Labeled and spaced forms are now recognized, while a bare nine digit number with no label is still ignored to avoid false positives.

Reproduce `a99b8cc`, fix `271aea7`. Found by: prompt injection harness, vendor egress case.

### INC-6: Burst alerts stopped at the threshold and undercounted PHI objects read

The window logic returned the first 50 events of a 60 object read, so the alert understated the scope of an exfiltration. That number drives breach assessment, so the alert now lists every event in any qualifying window (recall 83.5 percent to 100 percent).

Reproduce `fe7f181`, fix `ac87339`. Found by: detection scoring against labelled events.

### INC-7: Scanner categories with no control mapping made controls look clean

Twenty raw Checkov rule ids had no HIPAA mapping, so a control could show no open findings while a gap existed. Every category is now mapped, and the test fails if any new scanner output falls through.

Reproduce `fcb45a1`, fix `c9849aa`. Found by: control-map test against real scans.

### INC-8: Any signed-in member could read any other member's record and messages (BOLA)

`/members/<id>` looked up the id from the URL without comparing it to the signed-in member. Both routes now return 403 unless the token subject matches.

Reproduce `c0895ee`, fix `380e17b`. Found by: exploit test (no scanner flagged it until INC-17).

### INC-9: SQL injection in member search, and directory search open to every member

The search term was formatted into the SQL string. It is now a bound parameter, and the directory search is restricted to admins since a member has no reason to enumerate other members.

Reproduce `a733b42`, fix `cbe42f3`. Found by: exploit test, Bandit B608, custom Semgrep rule.

### INC-10: Export endpoint had no role check and a debug endpoint dumped the environment

`/admin/export` only checked that a token existed, and `/debug` returned every environment variable and the signing key. Export now requires the admin role and the debug route is removed.

Reproduce `b2850d1`, fix `da996be`. Found by: exploit test (no scanner flagged it until INC-17).

### INC-11: YAML import could construct Python objects and the vendor call skipped TLS verification

`yaml.load` with the full loader evaluated a tag that called a Python function, and `verify=False` allowed interception of PHI sent to a vendor. The code uses `yaml.safe_load` and verifies TLS with a timeout.

Reproduce `f583192`, fix `1a068ca`. Found by: Bandit B506 and B501, exploit test.

### INC-12: Credentials committed in source and passwords stored as unsalted MD5

AWS example keys, the signing secret and an MD5 password column were in the repository. Secrets now come from the environment and the service refuses to start without them; passwords use salted scrypt.

Reproduce `430d7a4`, fix `bd68f20`. Found by: detect-secrets, Bandit B105 and B324.

### INC-13: Tokens never expired and the signature was compared with !=

The token carried an exp claim that nothing checked, and the HMAC was compared with a normal string comparison. Expiry is enforced and the comparison is constant time.

Reproduce `3552809`, fix `0d4b036`. Found by: code review, exploit test with a shifted clock.

### INC-14: Terraform exposed PHI storage, the database and the cluster and granted Action * on *

A public S3 ACL, unencrypted public database, SSH open to the world, a public EKS endpoint without logging, a wildcard IAM policy and no CloudTrail. The rewrite is private, encrypted with a rotated KMS key, scoped to least privilege and audited, and Checkov findings fall from 44 to 10.

Reproduce `748b418`, fix `3e4b980`. Found by: Checkov (44 failed checks).

### INC-15: The secret scanner silently found nothing outside a git work tree

detect-secrets lists files with git ls-files, so scanning an exported archive or CI scratch directory printed nothing and exited 0, which looked like a clean result. The scan now uses --all-files, and the cache key includes how the tools are invoked so old empty results cannot be reused.

Reproduce `91c2251`, fix `645e0e6`. Found by: baseline scan from a scratch checkout.

### INC-16: Secret scanner flagged a Terraform boolean as a credential

detect-secrets' keyword detector matched `manage_master_user_password = true`, so the clean tree still carried a high-severity secret finding and the report could never reach zero secrets. The line carries an inline allowlist with a reason, scoped to that one line, and a test confirms the real seeded secrets in the baseline are still found.

Reproduce `825ca37`, fix `6151e9c`. Found by: remediated-tree scan.

### INC-17: The custom Semgrep rule for BOLA never matched anything

The first version of the rule used a route-string wildcard that Semgrep does not support in a decorator, so it silently matched nothing and no tool reported the worst flaw in the app. The rule now matches the route with a metavariable regex and a not-pattern for the ownership check, a second rule covers admin routes with no role check, and a test asserts that exactly the two vulnerable routes and the one admin route are caught on the baseline and nothing is caught on the fixed tree. The baseline is now scanned with the current rules, because scanning it with its own old rules would hide exactly this kind of fix.

Reproduce `41cc5cf`, fix `41d1b1a`. Found by: coverage test over the vulnerable baseline.

### INC-18: Report ordering changed between runs

The recurring-issue list was built from sets and a Counter, so categories with the same count came out in an order that depended on the hash seed, and a fresh clone produced a different report from the committed one. Ties are now ordered by count and then name, and a test runs several hash seeds in separate processes.

Reproduce `3fbebe7`, fix `f3ac3fe`. Found by: clean clone verification.

### INC-19: The committed report was different on every run

Fresh clones regenerated out/report.json with different random IAM key ids from moto, scratch-repo commit hashes that depend on the clock, and a set-ordered dictionary. Evidence that changes on every run cannot be diffed or reviewed, so volatile values are masked with fixed markers, ordering is sorted, and a test builds the report under two hash seeds in separate processes and requires identical output.

Reproduce `0e3807f`, fix `04c9b09`. Found by: clean clone verification, diffing two runs.
