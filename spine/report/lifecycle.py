"""Retirement mechanics — what stops a growing corpus from rotting.

Adding cases is the easy half. Without a story for taking them out, a corpus
accumulates material nobody prunes: cases every tool solves, a generator shape
tools have overfitted to, CVEs that were withdrawn upstream, and pins nobody has
looked at in three years. All four are invisible unless something counts them.

Four mechanisms, each deliberately conservative — none of them deletes anything:

**Retirement, not deletion.** A case that stops being trustworthy gets a
`retired: <reason>` and leaves the answer key. The YAML stays, so a scorecard
produced against an earlier corpus version remains explainable. A reason is
mandatory: `retired: true` records that someone stopped trusting a case and not
why, and the why is what a later reader needs.

**Saturation.** Once several tools have been scored, a case every tool finds and
none false-positives on carries no further information. It stays for regression
and drops out of the headline discriminating metrics. Two agreeing tools is a
coincidence, so the default threshold is three. A case *no* tool finds is not
saturated — that is the hard end of the corpus and the most informative material
in it.

**Monoculture ratio.** Most tier-1 cases come from one generator, and template
output shares a shape tools can overfit to. Tracking the hand-authored fraction
makes the drift visible rather than something discovered late.

**Pin staleness.** Pins are full SHAs and never move, which is the point — and
also means nothing tells you when one has rotted. A pin with no recorded date is
flagged too: silence about age is not evidence of freshness.
"""

from __future__ import annotations

import datetime
from enum import Enum


def retired_reason(case):
    """The reason a case was retired, or None if it is live.

    A retirement without a reason raises. The field exists to explain a decision
    to whoever reads the corpus later, and `retired: true` explains nothing.
    """
    if "retired" not in case:
        return None
    reason = case["retired"]
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(
            f"case {case.get('id', '<unknown>')} is retired with no reason; record "
            "why, because the reason is what a later reader needs")
    return reason


class Saturation(Enum):
    UNJUDGED = "unjudged"
    SATURATED = "saturated"
    DISCRIMINATING = "discriminating"


def saturation(results_by_tool, minimum=3):
    """Whether a case still separates tools.

    `results_by_tool` maps a tool name to whether it found the case. Saturated
    means every tool found it, so scoring it again tells nobody anything new.
    Everything else discriminates, including a case nobody found.
    """
    if len(results_by_tool) < minimum:
        return Saturation.UNJUDGED
    if all(results_by_tool.values()):
        return Saturation.SATURATED
    return Saturation.DISCRIMINATING


# Anything not produced by the template generator counts as authored: what the
# ratio measures is exposure to one generator's shape, and a CVE-derived case
# carries none of it.
GENERATED = {"generated"}
AUTHORED = {"hand-authored", "cve", "walkthrough"}


def authored_ratio(rows):
    """Fraction of cases that did not come out of the generator."""
    if not rows:
        return 0.0
    authored = sum(1 for row in rows if (row.get("source") or "") in AUTHORED)
    return authored / len(rows)


def _parse_date(text):
    try:
        return datetime.date.fromisoformat(text)
    except (TypeError, ValueError):
        return None


def stale_pins(sources, today, months=12):
    """Sources pinned longer ago than the threshold, or with no recorded date."""
    limit = _parse_date(today)
    if limit is None:
        return []
    cutoff = limit - datetime.timedelta(days=int(months * 30.44))
    stale = []
    for source in sources:
        pinned = _parse_date(source.get("pinned_on"))
        if pinned is None or pinned < cutoff:
            stale.append(source)
    return stale


def pin_age_warnings(sources, today, months=12):
    """Human-readable staleness report, empty when nothing is stale."""
    stale = stale_pins(sources, today, months)
    if not stale:
        return ""
    lines = [f"{len(stale)} pin(s) older than {months} months or undated:"]
    for source in sorted(stale, key=lambda s: s.get("name", "")):
        when = source.get("pinned_on") or "no date recorded"
        lines.append(f"  {source.get('name', '<unnamed>')}: {when}")
    lines.append("A pin that never moves is the point; one nobody has looked at "
                 "in that long is a different thing.")
    return "\n".join(lines) + "\n"
