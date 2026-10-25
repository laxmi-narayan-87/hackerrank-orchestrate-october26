# Evaluation report

## Scope and reproducibility

This report separates deterministic unit tests from real dataset evaluation. Hidden canonical labels are unavailable, so hidden-benchmark accuracy is **unknown** and is not inferred from public examples.

Commands to run from the repository root:

```bash
python3 -m unittest discover -s code/evaluation -p 'test_*.py' -v
python3 code/main.py --dataset dataset --input dataset/sample_deletion_requests.csv --output /tmp/sample_prediction.csv
python3 code/evaluation/main.py --input dataset/sample_deletion_requests.csv --output /tmp/sample_prediction.csv --dataset dataset --compare-sample
python3 code/main.py
python3 code/evaluation/main.py --input dataset/deletion_requests.csv --output output.csv --dataset dataset
```

## Tests and metrics

The synthetic test suite contains 13 checks for deletion intent, export/correction non-deletion requests, point-in-time filtering, exact identity matching, operation/state mapping, deduplication/numbering, active flows, restore risks, tombstone redaction, and invalid output rejection. These tests were executed in the isolated working directory and passed.

- Hidden benchmark status accuracy: **Unknown — hidden labels unavailable**.
- Hidden step-level accuracy: **Unknown — hidden labels unavailable**.
- Hidden field-level accuracy: **Unknown — hidden labels unavailable**.
- Hidden sequence accuracy: **Unknown — hidden labels unavailable**.
- Synthetic tests: **13 passed**.
- Full 518-case dataset run: **not executed here**; the local container could not resolve `github.com` to clone the dataset.
- Public sample comparison: **not measured here**; run the documented command in a checkout to record actual numbers.

## Additional scenarios authored

1. A data export request is `NOT_APPLICABLE`.
2. Near-match email addresses are not joined without an exact/historical/stable identifier.
3. Evidence captured after `audit_at` is excluded.
4. `DELETE_RECORD` must use phase `REMEDIATION` and state `ABSENT`.
5. A tombstone with direct identifiers is redacted, not indiscriminately deleted.
6. An enabled matching data flow is a recreation risk.
7. A restorable backup needs a restore-block plan.

## Known failure modes / improvements

- PDF/image OCR is not implemented.
- No parser match is not proof of absence; evidence coverage needs end-to-end review.
- Ambiguous identities should be reviewed rather than fuzzily joined.
- Legal-hold and retention decisions must be grounded in evidence at the audit time.
- Disable flows and block restores before changing dependent records.
- Do not claim hidden accuracy without hidden labels.
