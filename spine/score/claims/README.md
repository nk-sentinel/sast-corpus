# Capability claims

One file per tool, declaring the **languages** and **planes** it analyses, so
cases outside that are reported `n/a` instead of counted as false negatives.
`docs/THREATS-TO-VALIDITY.md`: *"A tool with no Swift support is not bad at
Swift."*

```bash
python3 spine/score/score.py results.sarif answers/expectedresults-1.0.csv \
    --claims spine/score/claims/sonarqube-community.json
```

Two rules, both enforced by `spine/score/claims.py`:

**A claim is capability, not quality.** `languages` and `planes` are facts about
what the product analyses. A `cwes` key is refused — "this tool does not do SQL
injection" is a statement about how good it is, and excluding those cases would
be marking its own homework. `tiers`, `severity` and `variants` are refused for
the same reason.

**A claim is declared before the run, and cites its source.** `source` must name
the vendor documentation or product output it came from, and it is printed in
every scorecard. A denominator narrowed after seeing the numbers is only
detectable if what it was narrowed by is on the record.

The files here are **drafts pending verification against each product**. Every
one needs its `source` confirmed and its `version`/`edition` filled in from the
instance actually used, before the run it scores. A claim carrying a guessed
language list is worse than no claim, because it looks authoritative.

| file | state |
|---|---|
| `semgrep-oss.json` | draft — confirm against the installed version's `--version` and supported-language list |
| `sonarqube-community.json` | draft — confirm edition; Community has no taint engine, which is a *capability* fact and belongs in `notes` |
| `endor-labs.json` | draft — no export seen yet |
| `aikido.json` | draft — no export seen yet |

A tool whose claim is not yet verified should be scored **without** `--claims`,
and the resulting harshness stated, rather than scored against a guess.
