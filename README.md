# Ghost Data Still Exists — deletion audit agent

This project implements a deterministic, evidence-driven audit pipeline for the HackerRank Orchestrate October 2026 challenge. It reads only participant-facing files under `dataset/`, resolves exact current and historical identifiers, applies each case's `audit_at` cutoff, inspects structured and unstructured evidence, and writes a contract-shaped `output.csv`. It proposes remediation only; it does not execute destructive operations.

## Design

- A request-intent gate rejects access/export, correction, login-help, and marketing opt-out requests that do not authorize account deletion.
- Identity resolution uses exact normalized email matches and historical email-change audit rows available at the audit cutoff. It avoids fuzzy email joins.
- Evidence parsing supports JSON bundles, SQLite-compatible SQL snapshots, text/log records, extractable PDFs, and optionally OCR'd images. Nested snapshot context and timestamps are propagated to records.
- Data-catalog identity links may establish a subject/resource relationship but are not treated as proof of the resulting state. Workflow and activity status strings are similarly treated as claims.
- Findings follow the permitted operation vocabulary and are ordered by phase and operation. Incomplete cases include proposed remediation and future verification with empty `evidence_id`; complete cases contain evidence-backed verification steps only.
- The solution is deterministic and offline; it makes no LLM/API calls. Therefore model input/output tokens and provider cost are zero.

## Run

Python 3.10+; no mandatory third-party dependencies.

```bash
python3 code/main.py
```

The program reads `dataset/deletion_requests.csv` and writes `output.csv` in the repository root. Custom run:

```bash
python3 code/main.py --dataset dataset --input dataset/sample_deletion_requests.csv --output /tmp/sample_prediction.csv
```

Optional support for PDFs/images:

```bash
python3 -m pip install pypdf pillow pytesseract
```

`pytesseract` also requires the Tesseract executable. If an optional extractor is missing, extraction for that file will be blank and the run remains deterministic; use this only where the environment has suitable runtime dependencies.

## Test and validate

```bash
python3 -m unittest discover -s code/evaluation -p 'test_*.py' -v
python3 code/evaluation/main.py --input dataset/deletion_requests.csv --output output.csv
python3 code/evaluation/main.py --input dataset/deletion_requests.csv --output output.csv --compare-sample
```

The validator checks exact columns, row count, sort order, duplicate/missing case IDs, JSON arrays, step schema, operation/state pairs, evidence requirements, and step numbering. `--compare-sample` separately reports status/step/field calibration on the public sample. Public-sample performance is not hidden-benchmark accuracy.

## Artifacts

The submission `code.zip` contains this README, executable code and tests, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`. Do not include `dataset/`, local credentials, virtual environments, cache directories, or nested archives. Root `output.csv` and `log.txt` are separate submission items.

## Limitations

The hidden grader's canonical outputs are unavailable to participants, so exact status/field/sequence accuracy on the 518-case target set cannot be claimed without that ground truth. This is a deterministic baseline with explicit uncertainty controls rather than a trained model; expand the evidence parsers in response to measured public-sample errors. No live MiroFish simulator is connected to this environment, so scenario simulation is performed with reproducible tests rather than an asserted MiroFish run.
