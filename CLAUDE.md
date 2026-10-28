# ZeroDay Sentinel

Flask vulnerability scanner for Hack Fest 2026 PS-01 (Zero-Day Vulnerability Detection).
Read, in this order: `docs/prd.md` (original PRD), `docs/decisions.md` (overrides the PRD where they differ), `docs/STATUS.md` (where we are).

## Who builds
Claude builds every layer in sequence. The human reviews at each gate and personally reads any code that executes target code (`app/verify/`).

## Rules
- Every layer reads and writes the `Finding` record in `backend/app/schema.py`. Do not change it without asking. Adding an optional field needs the human's OK and a note in `docs/decisions.md`.
- Scope: Python + Flask only. Bug classes: command injection (CWE-78), SQL injection (CWE-89), path traversal (CWE-22). Nothing else counts toward results.
- Defensive only. Never write working exploits. Proof tests use the harmless marker `ZDS_MARKER_<finding-id>`, run against `targets/` only, with sinks instrumented so nothing is really executed and nothing touches the network.
- No component is done without a pytest test. Run `cd backend && pytest -q` after every change. A red suite blocks the next step.
- Keep functions small (aim for under 40 lines). No new dependencies beyond the stack list in `docs/decisions.md` without asking.
- Never claim a number you have not produced by running code. Results tables must state the sample size.
- Secrets live in `.env`, which is git-ignored. Never commit tokens.

## Commands
- Backend: `cd backend && uvicorn app.main:app --reload`
- Tests: `cd backend && pytest -q`
- Frontend: `cd frontend && npm run dev`
- CLI scan: `python -m app.cli scan <path>` (from `backend/`)
- Eval: `python eval/run.py`

## Workflow per step (see docs/build-plan.md)
1. Read the step's prompt, its gate, and STATUS.md.
2. Plan: list files to touch and tests to write. Check the plan against the PRD and decisions.md.
3. Write the tests first where practical, then implement.
4. Run the full test suite. Fix until green.
5. Run the step's gate command and paste its output into STATUS.md.
6. Commit: `step-N: <layer> <what>`. Push.
7. Update STATUS.md (done, the gate evidence, any deviations), then move to the next step.

If a gate cannot be met within the step's time box, record the gap honestly in STATUS.md, cut scope per the step's fallback, and move on.

## Build order
0 Setup → 1 Targets → 2 Taint → 3 Wrappers → 4 Eval harness → 5 Severity+API → 6 Ingestion → 7 Frontend → 8 Early detection → 9 Proof+patch → 10 ML ranker → 11 Polish → 12 Stretch (fix-watcher).
Feature freeze at hour 20. Steps 0–7 are the minimum complete demo.
