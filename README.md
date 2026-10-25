# Ghost Data Still Exists — deletion audit agent

A deterministic, evidence-driven baseline for the HackerRank Orchestrate October 2026 challenge. It reads participant-facing data in `dataset/`, resolves exact current and historical identifiers, filters evidence by the audit cutoff, emits policy-oriented findings and proposed remediation, and writes `output.csv`. It never executes destructive operations.

## Design

- Common deletion, export/access, correction, and marketing opt-out intents are separated using bounded keyword patterns.
- Identity resolution uses normalized exact email matching and historical identity audit records available by `audit_at`; no fuzzy joins.
- Evidence ingestion supports JSON snapshots, SQLite-compatible SQL snapshots, and text/log records.
- PDF/image OCR is not implemented; files of those types are reported as unparsed warnings.
- Workflow status and generic activity success are not accepted as proof alone.
- The evaluator validates schema and scores the public 32-case sample. Hidden accuracy is unknown without organizer labels.
- No LLM/API calls are made, so inference usage/cost is zero.

## Run

Requires Python 3.10+ and no mandatory third-party dependencies.

```bash
python3 code/main.py
```

This writes root `output.csv` from `dataset/deletion_requests.csv`. To run the public sample:

```bash
python3 code/main.py --dataset dataset --input dataset/sample_deletion_requests.csv --output /tmp/sample_prediction.csv
python3 code/evaluation/main.py --input dataset/sample_deletion_requests.csv --output /tmp/sample_prediction.csv --dataset dataset --compare-sample
```

## Validate and test

```bash
python3 -m unittest discover -s code/evaluation -p 'test_*.py' -v
python3 code/evaluation/main.py --input dataset/deletion_requests.csv --output output.csv --dataset dataset
python3 code/evaluation/main.py --input dataset/deletion_requests.csv --output output.csv --dataset dataset --compare-sample
```

The validator checks column names, row count/IDs/order, statuses, JSON and step shape, allowed operation/phase/state combinations, consecutive step numbers, evidence references, and evidence-field rules. Public sample metrics are calibration only.

## Limitations and submission

This is a starting baseline, not a claim of a winning solution. It does not OCR PDFs/images, intent patterns are bounded, and a parser miss cannot prove absence. The public sample and all 518 cases must be run and reviewed before relying on the output. Hidden canonical labels are unavailable. No live MiroFish service is connected; simulations here mean deterministic test scenarios.

The challenge submission requires `code.zip`, root `output.csv`, an agent transcript, and an AI interview. Keep `dataset/`, secrets, environments, caches, and nested archives out of `code.zip`; follow `agent_trace_instructions.md` to prepare traces safely.
