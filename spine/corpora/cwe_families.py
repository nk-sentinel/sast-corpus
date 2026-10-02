"""One acceptable-CWE map, shared by every tier-3 derivation.

`acceptable_cwes` lists the weaknesses a scanner could *defensibly* report for a
case, so that a tool choosing a reasonable sibling is not scored down for its
taxonomy. The map therefore has to be a property of the weakness, not of the
dataset a case happened to come from.

It was not. `tier3.py` and `patcheval.py` each carried their own copy and they
had drifted apart on three entries:

    CWE-22   tier3 added CWE-35        patcheval did not
    CWE-79   tier3 added CWE-116       patcheval did not
    CWE-94   tier3 added CWE-78, 470   patcheval did not

The effect is the same defect that the CWE-94 widening produced on tier 1: a
Java path-traversal CVE accepted a CWE that a Go one did not, so a tool's score
moved with the provenance of the case rather than with what it found. Hence one
module, imported by both.

Where the two disagreed, the entry below was decided from the CWE hierarchy
rather than by taking a union:

- `CWE-35` ('.../...//') is a child of CWE-23, which is a child of CWE-22, so it
  is a legitimate, more specific answer for a path-traversal case. Kept.
- `CWE-116` (improper encoding or escaping of output) is what cross-site
  scripting *is*, viewed from the output side, and several engines label it that
  way. Kept.
- `CWE-78` is **not** in the code-injection family — it descends from CWE-77 and
  CWE-74 — and `CWE-470` (unsafe reflection) descends from CWE-610. Neither is a
  defensible answer for CWE-94, so both are dropped. This is the same call made
  for command injection on tier 1; see docs/MATCH-POLICY.md.
"""

FAMILIES = {
    # injection
    "CWE-89": ["CWE-89", "CWE-943", "CWE-564"],
    "CWE-78": ["CWE-78", "CWE-77", "CWE-88"],
    "CWE-77": ["CWE-77", "CWE-78", "CWE-88"],
    "CWE-94": ["CWE-94", "CWE-95", "CWE-96"],
    "CWE-95": ["CWE-95", "CWE-94"],
    # output encoding
    "CWE-79": ["CWE-79", "CWE-80", "CWE-83", "CWE-116"],
    # file and path
    "CWE-22": ["CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73"],
    "CWE-23": ["CWE-23", "CWE-22", "CWE-35", "CWE-36"],
    "CWE-73": ["CWE-73", "CWE-22", "CWE-23"],
    # parsing and deserialisation
    "CWE-502": ["CWE-502", "CWE-915"],
    "CWE-611": ["CWE-611", "CWE-827", "CWE-776"],
    # requests and redirects
    "CWE-918": ["CWE-918", "CWE-441"],
    "CWE-601": ["CWE-601", "CWE-1022"],
    # authorisation
    "CWE-862": ["CWE-862", "CWE-285", "CWE-863"],
    "CWE-863": ["CWE-863", "CWE-285", "CWE-862"],
}


def acceptable_for(cwe):
    """Every CWE a scanner could defensibly report for `cwe`, itself included.

    An unlisted weakness yields only itself. That is deliberate: inventing
    siblings for a class nobody has thought about would widen the match on a
    guess, and widening is exactly how a scorecard quietly starts flattering
    whichever tool prompted the change.
    """
    return list(FAMILIES.get(cwe, [cwe]))
