# Ghost Data Still Exists — deletion audit agent

This repository contains a deterministic, evidence-driven baseline for the HackerRank Orchestrate October 2026 challenge. It reads participant-facing inputs under `dataset/`, resolves exact current and historical identifiers, restricts evidence to each case's audit cutoff, applies policy-oriented classification, and writes `output.csv`. It only proposes remediation; it never executes destructive operations.

## Design

- The intent gate distinguishes deletion from common access/export, correction, and marketing opt-out requests. It supports several common languages but is not a general-purpose multilingual classifier.
- Identity resolution uses normalized exact email matching and historical identity audit rows available by `audit_at`; it intentionally avoids fuzzy joins.
- Evidence loading covers JSON snapshots, SQLite-compatible SQL snapshots, and text/log records. PDF and image OCR are not implemented; those files are reported as unparsed warnings.
- Workflow status and generic event success are not accepted as proof by themselves.
- The evaluator validates schema and compares only the published 32-case sample. Hidden-benchmark accuracy remains unknown without organizer labels.
- No LLM/API calls are made. Inference token usage and inference cost are zero.

## Run

Requires Python 3.10+ and no mandatory third-party dependencies.

```bash
python3 code/main.py
```

This reads `dataset/deletion_requests.csv` and writes root `output.csv`. For the public sample:

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

The validator checks headers, row IDs/count/order, allowed statuses, JSON/step shape, phase/state/operation mapping, step numbering, evidence IDs, and evidence requirements. Public-sample comparison is calibration only and cannot estimate hidden-benchmark accuracy.

## Submission and limitations

The challenge requires `code.zip`, root `output.csv`, an agent transcript, and an AI interview. Package runnable code and required reports without `dataset/`, credentials, virtual environments, caches, or nested archives; follow `agent_trace_instructions.md` for trace export and secret redaction.

The deterministic pipeline is a starting baseline, not an asserted winning solution. It does not OCR images/PDFs, intent patterns are bounded, and no parser match cannot prove absence. It needs end-to-end validation against the public sample and manual review of point-in-time evidence before relying on generated output. Hidden labels are not available. No live MiroFish connection is configured; simulation refers to deterministic test scenarios, not a live MiroFish run.
