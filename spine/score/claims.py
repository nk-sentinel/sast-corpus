#!/usr/bin/env python3
"""What a tool claims to analyse, so cases outside that are not scored as misses.

`docs/THREATS-TO-VALIDITY.md` is explicit: "A tool with no Swift support is not
bad at Swift. Cases in an unsupported language must be reported as `n/a` and
excluded from that tool's denominators — never counted as false negatives." The
same applies to planes: an engine that does not claim SCA should not be scored
on the `sca` plane.

Nothing implemented it. Every unsupported language counted as a false negative,
which would have distorted the headline comparison in a specific and unfair
direction — SonarQube Community analyses none of Swift, Rust or Kotlin, so it
would have absorbed 30 tier-1 false negatives for languages it never claimed,
and the incumbent would have looked worse than it is.

Two rules keep this from becoming a way to flatter a tool.

**A claim is about capability, not quality.** `languages` and `planes` are facts
about what the product analyses, and they must come from the vendor's own
documentation or the product's own language list — recorded in `source` so a
reader can check. A `cwes` key is rejected outright: "this tool does not do SQL
injection" is a statement about how good it is, and excluding those cases would
be marking its own homework.

**A claim is declared before the run.** It travels in the scorecard, so a claim
narrowed after seeing the numbers is visible in the diff. Fitting the denominator
to the result is indistinguishable, from the outside, from a tool doing well.

    python3 spine/score/score.py results.sarif answers/expectedresults-1.0.csv \\
        --claims spine/score/claims/sonarqube-community.json
"""

from __future__ import annotations

import json
from pathlib import Path

REQUIRED = ("tool", "languages", "planes", "source")
OPTIONAL = ("version", "edition", "ruleset", "tuning", "notes")
# A capability claim says which languages and planes the product analyses. It
# must not say which weaknesses it is good at.
REFUSED = {
    "cwes": "a CWE list would exclude cases on quality rather than capability",
    "cwe": "a CWE list would exclude cases on quality rather than capability",
    "tiers": "a tier is a realism level, not a product capability",
    "severity": "severity is a property of the weakness, not of the tool",
    "variants": "a variant is a mechanism within a CWE, not a product capability",
}


class ClaimError(ValueError):
    """The claim file is unusable. Never fall back to scoring everything.

    A claim that silently failed to load would score the tool on languages it
    does not support — the defect this module exists to fix — and the run would
    look normal. So this raises and the caller exits.
    """


def load(path):
    """Read and validate a claim file."""
    text = Path(path).read_text()
    try:
        data = json.loads(text)
    except ValueError as problem:
        raise ClaimError("{}: not valid JSON: {}".format(path, problem))

    if not isinstance(data, dict):
        raise ClaimError("{}: expected a JSON object".format(path))

    for key in sorted(data):
        if key in REFUSED:
            raise ClaimError("{}: '{}' is not allowed — {}".format(path, key, REFUSED[key]))
        if key not in REQUIRED + OPTIONAL:
            raise ClaimError("{}: unknown key '{}' (allowed: {})".format(
                path, key, ", ".join(sorted(REQUIRED + OPTIONAL))))

    for key in REQUIRED:
        if key not in data:
            raise ClaimError("{}: missing required key '{}'".format(path, key))

    for key in ("languages", "planes"):
        value = data[key]
        if not isinstance(value, list) or not value:
            raise ClaimError("{}: '{}' must be a non-empty list".format(path, key))
        if not all(isinstance(item, str) and item for item in value):
            raise ClaimError("{}: '{}' must be a list of strings".format(path, key))

    for key in ("tool", "source"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise ClaimError("{}: '{}' must be a non-empty string".format(path, key))

    return {
        "tool": data["tool"],
        "source": data["source"],
        "languages": sorted(set(data["languages"])),
        "planes": sorted(set(data["planes"])),
        **{key: data[key] for key in OPTIONAL if key in data},
    }


def applies(claim, case):
    """Whether `case` is inside what the tool claims to analyse.

    No claim means score everything, which is the long-standing behaviour and
    stays the default: a scorecard with no declared claim is still a valid
    scorecard, just a harsher one.
    """
    if claim is None:
        return True
    return case.language in claim["languages"] and case.plane in claim["planes"]


def partition(claim, cases):
    """(scored, not_applicable) — the cases to judge, and the cases to report."""
    if claim is None:
        return list(cases), []
    scored, excluded = [], []
    for case in cases:
        (scored if applies(claim, case) else excluded).append(case)
    return scored, excluded


def summarise(claim, excluded):
    """What the scorecard must say about the exclusion, so it is never silent.

    The reason is attributed, not merely tallied. A case is dropped when its
    language is unclaimed **or** its plane is, and reporting the language of
    every dropped case lists languages the tool does in fact analyse — a
    SonarQube claim covering java and dropping the `sca` plane would report
    "java excluded", which is false and would look like a narrowed denominator
    hiding behind a plane exclusion.
    """
    if claim is None:
        return None
    by_language = sorted({case.language for case in excluded
                          if case.language not in claim["languages"]})
    by_plane = sorted({case.plane for case in excluded
                       if case.plane not in claim["planes"]})
    return {
        "tool": claim["tool"],
        "source": claim["source"],
        "claimed_languages": claim["languages"],
        "claimed_planes": claim["planes"],
        "not_applicable": len(excluded),
        "excluded_languages": by_language,
        "excluded_planes": by_plane,
        **{key: claim[key] for key in OPTIONAL if key in claim},
    }
