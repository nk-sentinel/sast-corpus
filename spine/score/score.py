#!/usr/bin/env python3
"""Score a SAST run against the sast-corpus answer key.

Standard library only, single file, no network. A result must be reproducible
offline by anyone holding the corpus — including a vendor checking our numbers.

The match rules implemented here are the contract in docs/MATCH-POLICY.md. If
you change one, change the other in the same commit.
"""

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TOLERANCE = 10
BREAKDOWNS = ("language", "tier", "plane", "primary_cwe", "flow", "sanitizer", "obfuscation", "severity")

CWE_PATTERN = re.compile(r"\bcwe[-_/ ]?0*(\d+)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    """One reported location. A single SARIF result with several locations
    becomes several Findings sharing a result_key, so the scorer can collapse
    them and never award one result two true positives."""

    file: str
    start_line: int
    end_line: int
    cwes: frozenset = field(default_factory=frozenset)
    rule_id: str = ""
    tool: str = ""
    result_key: tuple = ()


@dataclass(frozen=True)
class Case:
    """One row of the answer key."""

    id: str
    label: str
    plane: str
    tier: int
    language: str
    framework: str
    primary_cwe: str
    acceptable_cwes: frozenset
    owasp_2021: str
    severity: str
    file: str
    start_line: int
    end_line: int
    alt_locations: tuple
    flow: str
    sanitizer: str
    obfuscation: str
    build_required: bool

    def locations(self):
        yield (self.file, self.start_line, self.end_line)
        for alt in self.alt_locations:
            yield alt


@dataclass
class Outcome:
    case: Case
    kind: str
    finding: object = None
    location_only: bool = False


@dataclass
class MatchReport:
    outcomes: list
    unmatched: list
    surplus: list

    def counts(self):
        tally = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for outcome in self.outcomes:
            tally[outcome.kind] += 1
        return tally


def match_findings(findings, cases, tolerance=10):
    """Assign findings to answer-key cases under docs/MATCH-POLICY.md.

    Assignment is greedy over candidate pairs ordered by quality: a CWE-bearing
    match beats a location-only one, and a closer line beats a distant one.
    Each case may be claimed once and each SARIF *result* may claim once, so
    neither a verbose tool nor a long ground-truth range can inflate the score.
    """
    candidates = []
    for case in cases:
        for finding in findings:
            quality = _candidate_quality(case, finding, tolerance)
            if quality is not None:
                location_only, distance = quality
                candidates.append((location_only, distance, case.id, finding.result_key, case, finding))

    candidates.sort(key=lambda c: (c[0], c[1], c[2], c[3]))

    claimed_cases = {}
    claimed_results = set()
    contested_results = set()

    for location_only, _distance, _case_id, result_key, case, finding in candidates:
        contested_results.add(result_key)
        if case.id in claimed_cases or result_key in claimed_results:
            continue
        claimed_cases[case.id] = (finding, location_only)
        claimed_results.add(result_key)

    outcomes = []
    for case in cases:
        claim = claimed_cases.get(case.id)
        if claim is None:
            outcomes.append(Outcome(case=case, kind="fn" if case.label == "vulnerable" else "tn"))
        else:
            finding, location_only = claim
            outcomes.append(
                Outcome(
                    case=case,
                    kind="tp" if case.label == "vulnerable" else "fp",
                    finding=finding,
                    location_only=bool(location_only),
                )
            )

    unmatched = [f for f in findings if f.result_key not in contested_results]
    surplus = [
        f
        for f in findings
        if f.result_key in contested_results and f.result_key not in claimed_results
    ]

    return MatchReport(outcomes=outcomes, unmatched=unmatched, surplus=surplus)


def load_answer_key(path):
    """Read expectedresults-<version>.csv into Cases."""
    cases = []
    with Path(path).open(newline="") as handle:
        for row in csv.DictReader(handle):
            cases.append(
                Case(
                    id=row["id"],
                    label=row["label"],
                    plane=row["plane"],
                    tier=int(row["tier"]),
                    language=row["language"],
                    framework=row["framework"],
                    primary_cwe=row["primary_cwe"],
                    acceptable_cwes=frozenset(_split(row["acceptable_cwes"])),
                    owasp_2021=row["owasp_2021"],
                    severity=row["severity"],
                    file=row["file"],
                    start_line=int(row["start_line"]),
                    end_line=int(row["end_line"]),
                    alt_locations=tuple(_parse_locations(row["alt_locations"])),
                    flow=row["flow"],
                    sanitizer=row["sanitizer"],
                    obfuscation=row["obfuscation"],
                    build_required=row["build_required"].strip().lower() == "true",
                )
            )
    return cases


def _split(cell):
    return [item for item in (cell or "").split(";") if item]


def _parse_locations(cell):
    for item in _split(cell):
        path, start, end = item.rsplit(":", 2)
        yield (path, int(start), int(end))


def scorecard(report, tolerance=DEFAULT_TOLERANCE, include_flow_locations=False):
    """Pooled metrics, per-dimension breakdowns, and the policy that produced them.

    The match policy travels with the numbers. A scorecard that does not state
    its tolerance and CWE rules is not comparable with anyone else's.
    """
    counts = report.counts()

    by = {dimension: group_counts(report, dimension) for dimension in BREAKDOWNS}

    return {
        "overall": metrics(counts),
        "by": {
            dimension: {key: metrics(value) for key, value in groups.items()}
            for dimension, groups in by.items()
        },
        "macro": {
            dimension: {
                metric: macro_average(groups, metric)
                for metric in ("precision", "recall", "f1", "f3", "tpr", "fpr", "youden_j")
            }
            for dimension, groups in by.items()
        },
        "narrative": narrative(report),
        "location_only_matches": sum(1 for o in report.outcomes if o.location_only),
        "unmatched_findings": len(report.unmatched),
        "surplus_findings": len(report.surplus),
        "match_policy": {
            "line_tolerance": tolerance,
            "cwe_rule": "tool CWE must appear in acceptable_cwes; findings with no CWE match on location alone",
            "path_rule": "answer-key path must equal the reported path or be a separator-anchored suffix of it",
            "dedup_rule": "one true positive per case; one claim per SARIF result",
            "include_flow_locations": include_flow_locations,
        },
    }


def metrics(counts):
    """Confusion matrix to headline figures.

    Undefined ratios report 0.0 and are named in `undefined`, so a tool that
    reported nothing is not quietly indistinguishable from one that reported
    perfectly. Never quote a composite on its own: published studies have found
    tools at 100% precision and under 25% recall at the same time.
    """
    tp, fp = counts.get("tp", 0), counts.get("fp", 0)
    fn, tn = counts.get("fn", 0), counts.get("tn", 0)

    undefined = []
    precision = _ratio(tp, tp + fp, "precision", undefined)
    recall = _ratio(tp, tp + fn, "recall", undefined)
    fpr = _ratio(fp, fp + tn, "fpr", undefined)

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": _f_beta(precision, recall, 1),
        "f3": _f_beta(precision, recall, 3),
        "tpr": recall,
        "fpr": fpr,
        "youden_j": recall - fpr,
        "undefined": undefined,
    }


def _ratio(numerator, denominator, name, undefined):
    if denominator == 0:
        undefined.append(name)
        return 0.0
    return numerator / denominator


def _f_beta(precision, recall, beta):
    weight = beta * beta
    denominator = weight * precision + recall
    if denominator == 0:
        return 0.0
    return (1 + weight) * precision * recall / denominator


def group_counts(report, dimension):
    """Split the confusion matrix by any Case attribute."""
    grouped = {}
    for outcome in report.outcomes:
        key = getattr(outcome.case, dimension)
        tally = grouped.setdefault(key, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        tally[outcome.kind] += 1
    return grouped


def macro_average(grouped_counts, metric):
    """Average a metric over categories, weighting each equally.

    A single huge category would otherwise mask a tool that is blind to a small
    one — which for a regulated stack is exactly the case worth knowing about.
    """
    if not grouped_counts:
        return 0.0
    values = [metrics(counts)[metric] for counts in grouped_counts.values()]
    return sum(values) / len(values)


def _candidate_quality(case, finding, tolerance):
    """(location_only, line_distance) if the finding could satisfy the case."""
    cwe_overlap = bool(finding.cwes & case.acceptable_cwes)
    if finding.cwes and not cwe_overlap:
        return None

    best = None
    for path, start, end in case.locations():
        if not paths_match(finding.file, path):
            continue
        if finding.start_line > end + tolerance or finding.end_line < start - tolerance:
            continue
        distance = min(abs(finding.start_line - start), abs(finding.start_line - end))
        best = distance if best is None else min(best, distance)

    if best is None:
        return None

    return (0 if cwe_overlap else 1, best)


def paths_match(reported, expected):
    """A tool's path may carry any prefix — a workspace root, a container mount.

    Suffix matching is anchored at a separator so `notier1/...` cannot satisfy
    `tier1/...`.
    """
    reported = normalise_path(reported)
    return reported == expected or reported.endswith("/" + expected)


def parse_sarif(doc, include_flow_locations=False):
    """Flatten a SARIF 2.1.0 log into Findings.

    Taint-path steps are excluded unless asked for: counting them by default
    would let a tool that emits a forty-step flow claim credit for anything
    along it, which measures verbosity rather than precision.
    """
    findings = []

    for run_index, run in enumerate(doc.get("runs") or []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name", "")
        rules = _rules_by_id(driver, run)
        cwe_taxonomy_guids = _cwe_taxonomy_guids(run)

        for result_index, result in enumerate(run.get("results") or []):
            rule = rules.get(result.get("ruleId"), {})
            cwes = frozenset(
                _cwes_from_rule(rule)
                | _cwes_from_properties(result.get("properties"))
                | _cwes_from_taxa(result.get("taxa"), cwe_taxonomy_guids)
            )
            key = (run_index, result_index)

            for location in _locations(result, include_flow_locations):
                findings.append(
                    Finding(
                        file=location[0],
                        start_line=location[1],
                        end_line=location[2],
                        cwes=cwes,
                        rule_id=result.get("ruleId", ""),
                        tool=tool_name,
                        result_key=key,
                    )
                )

    return findings


def _rules_by_id(driver, run):
    rules = {}
    for rule in driver.get("rules") or []:
        rules[rule.get("id")] = rule
    for extension in run.get("tool", {}).get("extensions") or []:
        for rule in extension.get("rules") or []:
            rules.setdefault(rule.get("id"), rule)
    return rules


def _cwe_taxonomy_guids(run):
    """GUIDs of taxonomies that are CWE, so taxa ids like '89' can be resolved."""
    guids = set()
    for taxonomy in run.get("taxonomies") or []:
        if (taxonomy.get("name") or "").upper() == "CWE":
            guids.add(taxonomy.get("guid"))
    return guids


def _cwes_from_rule(rule):
    found = _cwes_from_properties(rule.get("properties"))
    for relationship in rule.get("relationships") or []:
        target = relationship.get("target") or {}
        found |= _normalise_all([target.get("id"), *(target.get("toolComponent") or {}).values()])
    return found


def _cwes_from_properties(properties):
    if not properties:
        return set()

    candidates = []
    for key in ("cwe", "cwes", "tags", "cweId", "problem.severity"):
        value = properties.get(key)
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, (list, tuple)):
            candidates.extend(str(item) for item in value)

    return _normalise_all(candidates)


def _cwes_from_taxa(taxa, cwe_taxonomy_guids):
    found = set()
    for taxon in taxa or []:
        guid = (taxon.get("toolComponent") or {}).get("guid")
        identifier = str(taxon.get("id", ""))
        if guid in cwe_taxonomy_guids and identifier.isdigit():
            found.add("CWE-{}".format(int(identifier)))
        else:
            found |= _normalise_all([identifier, taxon.get("name")])
    return found


def _normalise_all(values):
    found = set()
    for value in values:
        if not isinstance(value, str):
            continue
        for number in CWE_PATTERN.findall(value):
            found.add("CWE-{}".format(int(number)))
    return found


def _locations(result, include_flow_locations):
    seen = []

    for location in result.get("locations") or []:
        parsed = _physical(location)
        if parsed:
            seen.append(parsed)

    if include_flow_locations:
        for flow in result.get("codeFlows") or []:
            for thread in flow.get("threadFlows") or []:
                for step in thread.get("locations") or []:
                    parsed = _physical(step.get("location") or {})
                    if parsed and parsed not in seen:
                        seen.append(parsed)

    return seen


def _physical(location):
    physical = location.get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri")
    region = physical.get("region") or {}
    start = region.get("startLine")

    if not uri or start is None:
        return None

    return (normalise_path(uri), int(start), int(region.get("endLine", start)))


def normalise_path(uri):
    """Reduce a SARIF artifact URI to a comparable path.

    Tools emit absolute paths, file:// URIs, and container-internal paths for
    the same file. Callers match by suffix, so only the scheme and leading
    './' need stripping here.
    """
    path = uri
    if path.startswith("file://"):
        path = path[len("file://") :]
    while path.startswith("./"):
        path = path[2:]
    return path.replace("\\", "/")


def narrative(report):
    """The counts a corpus owner actually asks for.

    Deliberately free of verdict: the corpus reports what happened and the
    reader decides whether it is good enough. A threshold baked in here would be
    one more thing to argue with.

    `false_alarms` and `not_judged` stay separate, and that distinction is the
    only one worth insisting on. A finding on a deliberate trap is a confirmed
    false positive — the corpus states that code is safe. A finding somewhere
    else may be a real issue the corpus does not know about, since cases exist
    only because someone thought to write them. Folding the second into the
    first would report the corpus's blind spots as the tool's mistakes.
    """
    counts = report.counts()
    return {
        "known_issues": counts["tp"] + counts["fn"],
        "found": counts["tp"],
        "missed": counts["fn"],
        "traps": counts["fp"] + counts["tn"],
        "false_alarms": counts["fp"],
        "traps_avoided": counts["tn"],
        "not_judged": len(report.unmatched),
        "duplicate_reports": len(report.surplus),
    }


def _plural(count, singular, plural=None):
    return singular if count == 1 else (plural or singular + "s")


def render_text(card, timing=None):
    """Human-readable scorecard: plain counts first, metrics after."""
    n = card["narrative"]
    overall = card["overall"]

    lines = [
        "WHAT THE CORPUS KNOWS",
        "  {:>6}  known {}".format(n["known_issues"], _plural(n["known_issues"], "issue")),
        "  {:>6}  {} that resemble issues but are not (traps)".format(
            n["traps"], _plural(n["traps"], "piece of code", "pieces of code")),
        "",
        "WHAT THE TOOL DID",
        "  {:>6}  found, of {} known {}".format(
            n["found"], n["known_issues"], _plural(n["known_issues"], "issue")),
        "  {:>6}  missed".format(n["missed"]),
        "  {:>6}  false {} — reported on code the corpus states is safe".format(
            n["false_alarms"], _plural(n["false_alarms"], "alarm")),
        "  {:>6}  reported outside the answer key — not judged either way".format(n["not_judged"]),
    ]

    if n["duplicate_reports"]:
        lines.append("  {:>6}  extra {} on issues already counted".format(
            n["duplicate_reports"], _plural(n["duplicate_reports"], "report")))

    if timing:
        summary = timing.get("summary", {})
        total = (summary.get("total") or {}).get("p50")
        loc = summary.get("scanned_loc")
        per_1k = (summary.get("seconds_per_1k_loc") or {}).get("total")
        lines += ["", "HOW LONG IT TOOK"]
        if total is not None:
            lines.append("  {:>6}  seconds (median of the timed runs)".format(round(total, 2)))
        if loc:
            lines.append("  {:>6}  scanned lines of code".format("{:,}".format(loc)))
        if per_1k is not None:
            lines.append("  {:>6}  seconds per 1k scanned lines".format(round(per_1k, 3)))

    lines += [
        "",
        "RATES",
        "  found {} of {} known issues".format(n["found"], n["known_issues"]),
        "  raised a false alarm on {} of {} traps".format(n["false_alarms"], n["traps"]),
        "  recall {:.3f}   precision {:.3f}   f1 {:.3f}   f3 {:.3f}".format(
            overall["recall"], overall["precision"], overall["f1"], overall["f3"]),
        "  tpr {:.3f}   fpr {:.3f}   youden j {:.3f}".format(
            overall["tpr"], overall["fpr"], overall["youden_j"]),
    ]

    if overall["undefined"]:
        lines.append("  undefined, reported as 0.0: {}".format(", ".join(overall["undefined"])))

    lines += [
        "",
        "HOW THESE WERE COUNTED",
        "  line tolerance +/-{}".format(card["match_policy"]["line_tolerance"]),
        "  {} {} matched on position because the tool emitted no CWE".format(
            card["location_only_matches"],
            _plural(card["location_only_matches"], "finding")),
    ]

    for dimension in ("tier", "language", "flow"):
        groups = card["by"].get(dimension) or {}
        if len(groups) < 2:
            continue
        lines += ["", "BY {}".format(dimension.upper())]
        for key in sorted(groups, key=str):
            m = groups[key]
            known = m["tp"] + m["fn"]
            lines.append("  {:<22} found {} of {:<4} false alarms {} of {}".format(
                str(key), m["tp"], known, m["fp"], m["fp"] + m["tn"]))

    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Score a SAST run against the sast-corpus answer key.")
    parser.add_argument("results", help="SARIF 2.1.0 file produced by the tool under test")
    parser.add_argument("answer_key", help="answers/expectedresults-<version>.csv")
    parser.add_argument("--tolerance", type=int, default=DEFAULT_TOLERANCE)
    parser.add_argument("--include-flow-locations", action="store_true",
                        help="also match taint-path steps; loosens matching, so state it when reporting")
    parser.add_argument("--strict", action="store_true",
                        help="treat missing results as zero findings rather than an error, so a crashed or timed-out scan scores as a failure to detect")
    parser.add_argument("--timing", type=Path, default=None,
                        help="a spine/timing/bench.py output file, to report scan time alongside")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    cases = load_answer_key(args.answer_key)
    results_path = Path(args.results)

    if results_path.is_file():
        findings = parse_sarif(json.loads(results_path.read_text()), args.include_flow_locations)
    elif args.strict:
        findings = []
    else:
        print("no such results file: {} (pass --strict to score it as a total miss)".format(results_path),
              file=sys.stderr)
        return 2

    report = match_findings(findings, cases, tolerance=args.tolerance)
    card = scorecard(report, tolerance=args.tolerance, include_flow_locations=args.include_flow_locations)

    timing = json.loads(args.timing.read_text()) if args.timing and args.timing.is_file() else None
    if timing:
        card["timing"] = timing.get("summary")

    print(json.dumps(card, indent=2) if args.json else render_text(card, timing))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
