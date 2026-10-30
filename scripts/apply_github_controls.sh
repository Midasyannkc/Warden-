#!/usr/bin/env bash
# Applies the repository controls defined in .github/ to a real GitHub repository.
# NOT run as part of this project (no GitHub access here). Usage: ./scripts/apply_github_controls.sh OWNER/REPO
set -euo pipefail
repo="${1:?usage: apply_github_controls.sh OWNER/REPO}"
gh api -X POST "repos/$repo/rulesets" --input .github/rulesets/main-protection.json
gh api -X PATCH "repos/$repo" -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
