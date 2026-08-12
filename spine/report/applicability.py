"""Which weaknesses can arise in which languages.

Coverage density measured against every possible cell understates the corpus,
because most cells are ones nobody should fill: use-after-free in Java and XXE
in C are not gaps. This turns a grid of 13 × 33 possibilities into the subset
that could honestly be filled, so a density figure means something.

The map is a claim about the world and the answer key is evidence, so the two
are checked against each other in CI. A tier-1 case that exists for a pair the
map calls inapplicable means one of them is wrong, and silently trusting either
is worse than failing. Tier 3 is exempt: those cases come from whatever CVEs the
upstream dataset happens to contain, which is evidence about the world rather
than about what we chose to author.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent / "applicability.json"


def load(path=DEFAULT_PATH):
    data = json.loads(Path(path).read_text())
    return {key: value for key, value in data.items() if not key.startswith("_")}


def applicable(mapping, language, cwe):
    """Whether a weakness can arise in a language.

    An unmapped weakness applies everywhere. Overstating the grid shows the
    weakness as a gap, which is visible and gets fixed; understating it would
    quietly shrink the denominator and flatter the coverage figure.
    """
    entry = mapping.get(cwe)
    if entry is None:
        return True
    return language in entry["applies_to"]


def applicable_cells(mapping, languages, cwes):
    return sum(1 for language in languages for cwe in cwes
               if applicable(mapping, language, cwe))


def density(grid, mapping, languages, cwes):
    """Filled fraction of the cells that could honestly be filled."""
    total = applicable_cells(mapping, languages, cwes)
    if not total:
        return 0.0
    filled = sum(1 for language in languages for cwe in cwes
                 if (language, cwe) in grid and applicable(mapping, language, cwe))
    return filled / total


def contradictions(rows, mapping):
    """Authored cases whose pair the map says cannot exist."""
    found = set()
    for row in rows:
        if row.get("tier") != "1":
            continue
        language, cwe = row["language"], row["primary_cwe"]
        if cwe in mapping and not applicable(mapping, language, cwe):
            found.add((language, cwe))
    return sorted(found)


def unmapped_cwes(rows, mapping):
    """Weaknesses present in the answer key with no entry in the map."""
    return sorted({row["primary_cwe"] for row in rows
                   if row["primary_cwe"] and row["primary_cwe"] not in mapping})
