# Deterministic scenario simulation and failure review

## Simulation boundary

No live MiroFish backend is connected, so this is not a MiroFish run. Deterministic tests cover the bounded scenarios below.

| Scenario | Perturbation | Expected behavior | Evidence |
|---|---|---|---|
| Non-deletion intent | User asks only for export | `NOT_APPLICABLE`, steps `[]` | Intent test and validator |
| Near-match email | Evidence has similar but different email | Do not fuzzy-join | Identity test |
| Future evidence | Capture later than `audit_at` | Exclude evidence | Cutoff test |
| Active flow | Connector explicitly enabled | Report flow; propose disable | Classification test |
| Restore path | Backup restore allowed | Report restore risk | Classification test |
| Tombstone PII | Stable reference plus identifiers | Redact without dropping stable reference | Classification test |
| Invalid output | Wrong operation/state or N/A with steps | Validator rejects | Negative tests |

## Failure loop

- Starter `code/main.py` and `code/evaluation/main.py` were empty.
- First local tests surfaced an import setup issue; registering dynamically imported modules fixed it.
- Two negative test fixtures initially had malformed CSV quoting; corrected fixtures.
- After these fixes, 13 synthetic tests passed.
- Full sample comparison and full 518-case generation were not executed in this environment because the local container could not clone from GitHub and does not contain the dataset. Dataset-level metrics are **not measured**, not passed.

## Next loop

1. Run the tests in a full checkout.
2. Produce a prediction for the 32 public samples and compare every mismatch against `sample_output.csv`.
3. Generate the full output and validate the structure.
4. Manually inspect evidence warnings and cases involving history, support messages, tombstones, flows, backups, and cutoff timing.
5. Report actual measured metrics and fix the largest repeatable failure.

Valid JSON is not evidence of accurate statuses. Public sample metrics are diagnostic only; hidden accuracy remains unknown.
