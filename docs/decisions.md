# Decisions and PRD amendments

These override `docs/prd.md` where they conflict. Every entry gives the PRD gap and the decision.

## D1. Build order
**Gap:** the order in CLAUDE.md (L3 → L4 → frontend) contradicts the step table (frontend at step 6).
**Decision:** one builder works sequentially, with Must items before Should items:
Setup, Targets, L2 taint, L2 wrappers, Eval harness, L5 severity + API, L1 ingestion, Frontend, L3 early detection, L4 proof + patch, L2 ML ranker, Polish, Stretch.
The eval harness moves early because it validates the core claim (we catch wrapper bugs that Bandit and Semgrep miss) before anything is built on top of it.

## D2. Scope of sinks and rules
**Gap:** `pickle.loads`, secrets and weak crypto sit outside the three stated bug classes.
**Decision:**
- Drop `pickle.loads` from v1 sinks.
- The rule layer runs Semgrep and AST checks for secrets and weak crypto as `detector: "baseline-rule"`. These are shown in the UI but excluded from every reported metric.

## D3. Severity formula
**Gap:** `base(CWE)` and the numeric value of `confidence` are undefined.
**Decision:**
`severity = min(10, base + 1.5*reachable + 1.0*public_route + 1.0*confidence - 2.0*sanitizer_present)`, floored at 0 and rounded to 1 decimal.

| CWE | base |
|---|---|
| CWE-78 | 6.0 |
| CWE-89 | 5.5 |
| CWE-22 | 5.0 |

- `confidence`: pattern-match = 0.0, reachable = 0.5, proof-confirmed = 1.0.
- `reachable` = 1 if a path exists from a Flask route source to the sink.
- `public_route` = 1 if the route has no auth decorator (`login_required` or similar).
- `sanitizer_present` = 1 if a sanitizer sits on the path but appears incomplete (for example, the wrong sanitizer for the sink type).

Every term is stored in `severity_factors`.

## D4. Proof runner without real execution
**Gap:** Docker may not be available in the build environment, and running injected commands, even harmless ones, is risky.
**Decision:** the primary proof runner loads the target app with the Flask `test_client`. Before loading, it monkeypatches the sinks (`os.system`, `subprocess.*`, `sqlite3`/`cursor.execute`, `open`, `os.path.join`) with recorders that log their arguments and never execute them. The marker is sent through the route, and the proof passes if the marker appears in a recorded sink argument. Network is disabled with a socket guard.
A Docker wrapper (`--network none`) is optional and used if Docker is present. The human reviews `app/verify/` before the first run.

## D5. ML ranker data
**Gap:** three seeded apps are not enough for a project-level split.
**Decision:** a generator (`eval/gen_variants.py`) creates at least 30 small Flask projects from templates. Each one mixes vulnerable, sanitized and dead-code paths, and is labelled automatically.
- Train on generated projects A–T.
- Test on projects U–Z plus the three hand-written targets, which are never used for training.
- Report false-positive reduction at equal recall.
- If the gain is under 10%, ship the ranker as "experimental" and say so on the slide.

## D6. Stack (allowed dependencies)
- Backend: fastapi, uvicorn, pydantic, sqlite3 (stdlib), scikit-learn, semgrep, bandit, reportlab (for PDF), jsonschema (for SARIF validation), pytest, httpx, flask (for the targets), gitpython.
- Frontend: React + Vite, recharts.

## D7. Snippet scanner
A pasted function is wrapped into `app.py` with a stub `from flask import Flask, request; app = Flask(__name__)`. Undefined helper names are treated as unresolved calls and get a `pattern-match` confidence tier. They are never silently dropped.

## D8. Repo and CI
- Code lives in a new GitHub repo, with commits after each green step.
- The PR-scan Action runs on a demo PR that introduces a vulnerable commit, to show early detection live.

## D9. Extra sinks for path traversal and command injection
**Gap:** the PRD sink list (`open`, path joins) misses common Flask file sinks.
**Decision:** add `send_file`, `send_from_directory` (without a safe base), `shutil.copy*`, `shutil.move`, `os.remove`/`os.unlink` for CWE-22; `os.popen` for CWE-78; `executescript`/`executemany` for CWE-89.

## D10. Headline claim
**Gap:** the PRD says we find wrapper bugs that Bandit misses. Bandit pattern-matches command sinks everywhere, so it hits some wrapper sink lines (without knowing the source).
**Decision:** the headline compares recall on wrapper bugs and precision, and shows the source-to-sink path as something Bandit cannot give. Numbers come only from `eval/run.py`.
