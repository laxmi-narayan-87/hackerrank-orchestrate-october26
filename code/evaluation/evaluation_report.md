# Evaluation report

## Scope and reproducibility

This report distinguishes structural validation and deliberately constructed tests from benchmark performance. The hidden canonical answers are unavailable, so hidden-benchmark accuracy is **unknown** and is not inferred from public examples.

Run from the repository root:

```bash
python3 -m unittest discover -s code/evaluation -p 'test_*.py' -v
python3 code/main.py --dataset dataset --input dataset/sample_deletion_requests.csv --output /tmp/sample_prediction.csv
python3 code/evaluation/main.py --input dataset/sample_deletion_requests.csv --output /tmp/sample_prediction.csv --dataset dataset --compare-sample
python3 code/main.py
python3 code/evaluation/main.py --input dataset/deletion_requests.csv --output output.csv --dataset dataset
```

## Test evidence

The synthetic test suite contains 13 checks covering English/French deletion intent, export/correction non-deletion requests, point-in-time cutoff filtering, exact rather than fuzzy identity matching, operation/state mapping, deduplication and step numbering, active data flows, restore risks, tombstone redaction, invalid phase/state rejection, and the `NOT_APPLICABLE` empty-step rule. The isolated local suite passed 13 tests after fixing import and CSV fixture issues.

## Metrics

- Hidden benchmark case/status accuracy: **Unknown — hidden labels are unavailable**.
- Hidden step-level accuracy: **Unknown — hidden labels are unavailable**.
- Hidden field-level accuracy: **Unknown — hidden labels are unavailable**.
- Hidden sequence accuracy: **Unknown — hidden labels are unavailable**.
- Synthetic unit tests: **13 passed** in the isolated local workspace.
- Full 518-case output: **not run against the repository dataset here**; this container cannot resolve `github.com` to clone the repository, and the dataset is not mounted locally. Run generation and structural validation in a checkout of `main` before submission.
- Public-sample comparison: **not measured here** for the same data-access limitation. Run the documented command and record actual results before relying on generated output.

## Additional scenarios created for testing

1. Intent separation: a request only asking for data export must return `NOT_APPLICABLE`.
2. No fuzzy identity joins: `person.jr@example.com` must not be linked to `person@example.com` without an exact/history/stable-ID relationship.
3. Point-in-time cutoff: evidence captured after `audit_at` must not change the decision.
4. Policy-state pairing: `DELETE_RECORD` must be `REMEDIATION/ABSENT`; the validator rejects mismatches.
5. Tombstone treatment: a retained tombstone with direct identifiers must be redacted, not indiscriminately deleted.
6. Unsafe integration: a matching enabled connector is a recreation risk.
7. Restorable backup: a backup with `restore_allowed=true` requires a restore-block plan.

## Known failure modes and improvements

- **Multimodal evidence:** PDF/image OCR is not implemented. Add extraction with tests for parsed identifiers.
- **Evidence completeness:** no parser match is not proof of absence. Expand parsers and rely on explicit read-back state.
- **Identity ambiguity:** ambiguous cases should be reviewed rather than fuzzily joined.
- **Conditional policy:** legal holds and retention windows must be tied to evidence and audit time.
- **Causal ordering:** disable data flows and block restores before changing dependent copies; then verify every affected resource.
- **Metrics integrity:** do not claim hidden accuracy without hidden labels or infer it from case families.
