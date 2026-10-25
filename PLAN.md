# Sample Audit Accuracy Plan

## Goal
Improve the deletion-audit baseline's evidence and policy handling without using organizer-only data or hardcoded case labels. Success is measured by unit tests, public-sample status/step metrics, structural validation, and CI execution.

## Recon findings
- `code/main.py` parses JSON and SQL evidence but does not load `dataset/system_activity.csv` as a first-class evidence stream.
- `classify()` treats every support record alike, and analytics/telemetry records can be called anonymized when they still link to a subject via `user_id`/customer reference.
- Retention handling currently marks all security records retained regardless of supplied retention fields and does not distinguish active legal holds.
- Current pipeline has a structural validator and sample comparison; sample comparison must be run against the separate 32-case sample, not the 518-case output file.

## Scope
- Make category classification respect record metadata and policy semantics.
- Add conservative, timestamp-aware handling of explicit activity checks for data-flow and restore state; generic SUCCESS/FAILED events are not state proof.
- Improve log matching only where an identifier and resource are grounded in the same trace.
- Add regression tests for policy edge cases and temporal activity evidence.
- Update evaluation notes with actual CI measurements after a run.

## Non-goals
- No model training, invented labels, OCR claims, hidden-answer inference, or broad rewrite.
- No automatic merge to main. Prepare a reviewable PR and inspect CI before proposing merge.
- No edits to challenge datasets or organizer-only content.

## Acceptance criteria
1. Existing unit tests pass and new regression tests cover the changes.
2. Public-sample status, exact-step, and sequence metrics are recorded from an actual run.
3. The 518-case output validates structurally with 518 unique sorted rows and only allowed operations/evidence references.
4. No evidence later than a case's `audit_at` influences its result.
5. Changes remain bounded to code/tests/reports and this plan.

## Execution
1. Implement policy-aware classification and explicit activity evidence.
2. Run CI by opening a PR (repository workflow runs tests, generates output, validates, and scores sample).
3. Inspect logs and artifacts; revise at most two times if deterministic failures appear.
4. Record measured results and remaining limitations. Keep the PR unmerged pending user review.
