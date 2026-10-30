"""CODEOWNERS parsing with GitHub's rule: the last matching pattern wins."""
from __future__ import annotations

import fnmatch
import re


def parse(text: str) -> list[tuple[str, list[str]]]:
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        rules.append((parts[0], parts[1:]))
    return rules


def _matches(pattern: str, path: str) -> bool:
    anchored = pattern.startswith("/")
    pat = pattern.lstrip("/")
    if pat == "*":
        return True
    if pat.endswith("/"):
        return path.startswith(pat) if anchored else (path.startswith(pat) or ("/" + pat) in ("/" + path))
    rx = fnmatch.translate(pat).replace(r"\Z", "")
    return bool(re.match(rx, path)) or (not anchored and fnmatch.fnmatch(path.split("/")[-1], pat))


def owners_for(rules, path: str) -> list[str]:
    result: list[str] = []
    for pattern, owners in rules:
        if _matches(pattern, path):
            result = owners
    return result


def is_sensitive(rules, path: str) -> bool:
    """A path is sensitive when something more specific than the catch-all claims it."""
    catch_all = next((o for p, o in rules if p == "*"), [])
    return owners_for(rules, path) != catch_all


def lint(rules) -> list[str]:
    """Report patterns that can never take effect because a later, broader pattern
    matches the same paths and wins. GitHub applies the last match."""
    problems = []
    for i, (pat, _) in enumerate(rules):
        if pat == "*":
            continue
        for later_pat, _ in rules[i + 1:]:
            if later_pat == "*":
                problems.append(f"{pat} is shadowed by the later catch-all *")
                break
    return problems
