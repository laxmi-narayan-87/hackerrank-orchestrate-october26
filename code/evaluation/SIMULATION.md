# Deterministic scenario simulation and failure review

## Simulation boundary

No connected MiroFish service is available here, so this is not a live MiroFish run and no multi-agent forecast is claimed. These are deterministic contract scenarios covered by tests or intended validation checks.

| Scenario | Perturbation | Expected behavior | Verification |
|---|---|---|---|
| Non-deletion intent | Request asks only for export | `NOT_APPLICABLE`, steps `[]` | Intent test and validator |
| Similar email | Evidence is only a near-match | Do not use fuzzy joins | Exact identity test |
| Future evidence | Capture time is after `audit_at` | Exclude evidence | Cutoff test |
| Active flow | Matching connector enabled | Report flow; propose disable and verify | Classification test |
| Backup restore | Backup restore allowed | Report restore risk | Classification test |
| Tombstone PII | Stable reference plus direct IDs | Redact without deleting stable reference | Classification test |
| Invalid output | Wrong op/state or non-empty N/A steps | Validator rejects | Negative validator tests |

## Findings from the development loop

- Initially, both Python entry points were empty even though the README described a full pipeline.
- The first local test run failed because dynamically imported dataclasses were not registered in `sys.modules`; the harness was fixed.
- Two negative tests initially failed because their CSV fixtures were malformed; fixtures were corrected.
- The local test suite then reported 13 passing tests.
- A full public-sample score and 518-case run have not been produced: this isolated container cannot resolve `github.com` to clone the repository and the dataset is not mounted locally. The GitHub connector can inspect and write code but does not execute it. Dataset-level metrics are therefore **not measured**, not passed.

## Next empirical loop

1. In a checkout of `main`, run the unit suite.
2. Generate the 32-case public sample and run `--compare-sample`; review every mismatch.
3. Generate the full output and run the structural validator.
4. Review evidence warnings and sample cases with historical emails, support data, tombstones, active flows, backups, and cutoff boundaries.
5. Record actual metrics and fix the largest repeatable error category before submission.

Syntactic validity is not evidence that predicted statuses are accurate. Public sample metrics are diagnostic only; hidden accuracy remains unknown.
