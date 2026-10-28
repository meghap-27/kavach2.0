# Build plan: layer prompts and gates

Claude runs these in order, following the per-step workflow in CLAUDE.md. Each step has a time box (in hackathon hours), a prompt, a gate (a command that must pass, with its evidence pasted into STATUS.md) and a fallback if the time box runs out.

| # | Hours | Layer |
|---|---|---|
| 0 | 0.0–0.5 | Setup |
| 1 | 0.5–1.5 | Targets |
| 2 | 1.5–4.0 | L2 taint |
| 3 | 4.0–6.0 | L2 wrappers |
| 4 | 6.0–7.0 | Eval harness |
| 5 | 7.0–9.0 | L5 severity + API |
| 6 | 9.0–10.0 | L1 ingestion |
| 7 | 10.0–13.0 | Frontend (crude end to end by hour 13) |
| 8 | 13.0–15.5 | L3 early detection |
| 9 | 15.5–17.5 | L4 proof + patch |
| 10 | 17.5–19.0 | L2 ML ranker |
| 11 | 19.0–20.0 | Polish (freeze at hour 20) |
| — | 20.0–21.0 | Cache demo results, record backup video (human) |
| 12 | 21.0+ | Stretch, only if everything above is green |
| — | 21–24 | Rehearse, deck, limitations slide |

---

## Step 0: Setup
**Prompt:** Read docs/prd.md and docs/decisions.md. Scaffold the repo layout from PRD §11. Write `backend/app/schema.py` as a pydantic v2 `Finding` model matching PRD §7 exactly:
- `confidence_tier`, `status` and `detected_at` as Literal enums
- `path` as `list[str]`
- `severity_factors` as `dict[str, float]`

Add `requirements.txt` (per D6), `.gitignore` (venv, .env, node_modules, `*.db`), pytest config, and a test that round-trips a sample Finding to and from JSON. Do not implement features.

**Gate:** `pytest -q` is green, and `python -c "from app.schema import Finding"` works.

**Fallback:** none. This step must pass.

## Step 1: Targets
**Prompt:** Create three small, intentionally vulnerable Flask apps in `targets/`: `cmd_app`, `sqli_app` and `path_app`. Each needs:
- 2 direct bugs (source to sink in the same function)
- 2 wrapper bugs, where the source passes through 1–3 custom helpers before the sink, with names Bandit would not flag
- 1 correctly sanitized path (a negative case)
- 1 unreachable vulnerable helper (a dead-code negative)

Write `targets/ground_truth.json` listing every bug: id, file, line, cwe, kind (direct, wrapper or negative), and the expected path. Add a test that every ground-truth line exists and contains the named sink.

**Gate:** `pytest tests/test_targets.py` is green, and the ground truth lists at least 12 positive and 6 negative cases.

**Fallback:** none.

## Step 2: L2 parser, call graph and taint
**Prompt:** Implement `app/detect/callgraph.py`:
- Use `ast` to collect functions, intra-project calls (resolved across modules via imports) and Flask routes (`@app.route`, `@bp.route`, plus methods).
- Flag dynamic calls (`getattr`, calls on unresolved attributes) as unresolved.

Implement `app/detect/taint.py`:
- Sources: `request.args`, `.form`, `.values`, `.json`, `.get_json()`, `.cookies`, `.headers`, `.files[...].filename`, and route path parameters.
- Propagation: assignments, augmented assignments, string concatenation, `%`, `.format`, f-strings, containers, and argument passing into resolved callees.
- Sinks per decisions D2.
- Sanitizers: `shlex.quote` (CWE-78 only), parameterized `execute(sql, params)` (CWE-89), `secure_filename` or `realpath` plus a `startswith` prefix check (CWE-22).

Emit Finding records with `detector="taint-direct"`. Tests run against `targets/` and score against ground truth.

**Gate:** all `direct` bugs found, and zero findings on `sanitized` negatives.

**Fallback:** if cross-module resolution slips, support same-module calls plus `from x import y`, and log a limitation.

## Step 3: L2 wrapper discovery
**Prompt:** Implement `app/detect/wrappers.py`:
- Compute per-function taint summaries: which parameters reach which sink class, unsanitized.
- Iterate to a fixpoint up the call graph so a function that passes a parameter to a summarized function inherits that summary.
- Treat summarized functions as project-specific sinks.
- Emit findings with `detector="taint-wrapper"` and the full call path.
- Report unreachable wrappers (no route source) only as `pattern-match`, never as reachable.

Add tests for each wrapper bug and for the dead-code negative.

**Gate:** 100% of `wrapper` positives found, and dead-code helpers are not marked reachable.

**Fallback:** limit propagation depth to 4 and document it.

## Step 4: Eval harness (early, to validate the claim)
**Prompt:** Write `eval/run.py`:
- Run Bandit (`bandit -r -f json`), default Semgrep (`semgrep --config p/python --json`; if offline, `p/default` or bundled rules, and note which in the output) and our CLI on `targets/`.
- Match findings to ground truth by file and a line window of ±2 with the same CWE.
- Output `eval/results.md` and `eval/results.json` with caught, missed and precision per tool, split into direct and wrapper.
- Print `n=` sample sizes.

**Gate:** the table is generated. If our scanner does not beat both baselines on wrapper bugs, stop and tell the human before continuing, because the core claim is at risk.

**Fallback:** none. This is the main claim.

## Step 5: L5 severity, tagging and API
**Prompt:**
- `app/report/severity.py`: the formula from D3.
- `app/report/owasp.py`: mapping CWE-78, 89 and 22 to `A03:2021 Injection` and `A01:2021 Broken Access Control`; CWE-22 maps to A01.
- `app/store.py`: SQLite storage for scans and findings.
- `app/main.py`: FastAPI endpoints from PRD §8 L5. Scans run in a background task. `PATCH /findings/{id}` changes only `status`.
- `app/cli.py`: `scan <path>` prints findings and exits non-zero at severity ≥ 7.

Add API tests with httpx `TestClient`.

**Gate:** POST a scan of `targets/` and GET the findings, which return graded, tagged records. All tests green.

**Fallback:** skip the background task and run scans synchronously.

## Step 6: L1 ingestion
**Prompt:** Implement `app/ingest/`:
- Zip upload: 50 MB cap, zip-slip protection, extraction into `workspace/<scan_id>`.
- GitHub URL: shallow clone via gitpython, 30 s timeout, `https://github.com/` only.
- File filter: skip `venv`, `.venv`, `site-packages`, `tests`, `node_modules` and vendored code; skip non-`.py` files, reporting counts back to the user.
- Diff reader: map changed lines from a git diff or staged files to function names.
- Snippet: wrap per D7, available at `POST /snippet`.

Add tests: oversized zip, zip-slip, snippet missing imports, diff mapping.

**Gate:** zip upload of a target scans end to end through the API.

**Fallback:** if GitHub clone is blocked in the build environment, test with a local bare repo and note that.

## Step 7: Frontend
**Prompt:** Build a React + Vite app in `frontend/` with three pages:
- Scan page: upload a zip, paste a GitHub URL or paste a snippet.
- Findings table: filters for CWE, severity, tier, status and detector.
- Finding detail: the source-to-sink path shown as clickable steps with highlighted code lines, the severity breakdown from `severity_factors`, the fix suggestion and a status dropdown.

Use the API through a Vite proxy. Keep styling clean and minimal.

**Gate:** crude end to end works: upload, findings, detail, and changing a status persists. Checked with a screenshot.

**Fallback:** drop charts. The table and detail are enough.

## Step 8: L3 early detection
**Prompt:**
- `app/early/incremental.py`: cache per-function summaries keyed by a hash of the function's source. On a diff, re-analyse changed functions and their transitive callers only.
- `app/early/hook.py`: pre-commit script that scans staged files, prints findings, exits 1 at severity ≥ 7, and honours `ZDS_SKIP=1` as the bypass.
- `.github/workflows/scan.yml`: on `pull_request`, scan the diff, post review comments on changed lines and upload SARIF via `github/codeql-action/upload-sarif`.
- Add `bench/diff_timing.py` to measure the median diff-scan time over 20 seeded commits.

**Gate:** median diff scan under 5 s, the hook blocks a vulnerable commit in a test repo, and the Action YAML lints.

**Fallback:** if PR comments are hard to get working, rely on SARIF upload alone, since it still annotates the PR.

## Step 9: L4 proof, patch and tiers
**Prompt:**
- `app/verify/proof.py` per D4: instrumented sinks, Flask test client, marker `ZDS_MARKER_<id>`, socket guard, 10 s timeout, run in a subprocess.
- `app/verify/patch.py`: template fixes per CWE:
  - CWE-78: replace a `shell=True` string with an argument list or `shlex.quote`
  - CWE-89: parameterize the query
  - CWE-22: `secure_filename` plus a realpath prefix check

  Apply the fix to a copy of the project and re-run the proof. Return a unified diff labelled "suggestion".
- Update `confidence_tier`: proof-confirmed if the marker reached the sink, reachable if a path exists but no proof was possible, pattern-match otherwise. Never drop a finding. Recompute severity.

**Stop and ask the human to review `app/verify/` before the first run.**

**Gate:** for every high-severity target finding, the proof passes before the patch and fails after it (the marker no longer reaches the sink). Findings that can't be proven keep a lower tier.

**Fallback:** prove direct bugs only, and give wrapper bugs the reachable tier.

## Step 10: L2 ML ranker
**Prompt:**
- `eval/gen_variants.py`: generate at least 30 labelled projects per D5.
- `app/detect/ranker.py`: features per finding:
  - path length, number of helpers, sanitizer seen, sink class, source type
  - route has auth, unresolved calls on the path, string-building type, dead code
- Train a `GradientBoostingClassifier` (or logistic regression) using a project-level split per D5. Save it to `models/ranker.pkl` and set `ml_rank` on each finding.
- Report false-positive reduction at equal recall in `eval/ml.md`.

**Gate:** a number is recorded with its sample size, whatever that number turns out to be.

**Fallback:** ship the ranker as experimental if the gain is under 10%.

## Step 11: Polish (stop at hour 20)
**Prompt:**
- Add dashboard charts: by CWE, by severity and by detector.
- Add the status workflow UI.
- Export PDF (reportlab) and JSON.
- Export SARIF 2.1.0, validated against the official schema with jsonschema, plus a test for it.
- Add an ablation table in eval: rules only, taint only, taint + ML, taint + proof.

**Gate:** exports open, SARIF validates, and the ablation table is generated.

## Step 12: Stretch, fix-watcher (only if everything above is green)
**Prompt:** `app/early/fixwatch.py`:
- For pinned dependencies, fetch recent commits.
- Rank them by diff heuristics (a sanitizer added near a sink).
- Derive a Semgrep pattern from the change.
- Accept the pattern only if it matches the vulnerable version and not the patched one.
- Emit lead findings with `detected_at="watch"`, labelled as leads.

**Gate:** one accepted rule demonstrated on the stripped historical fix.

---

## Demo checklist (PRD §16)
- [ ] All seeded wrapper bugs found; the Bandit and Semgrep comparison is recorded with n
- [ ] Results state the small sample size
- [ ] The hook flags a vulnerable commit in under 5 s
- [ ] The proof fails to block the marker before the patch and blocks it after
- [ ] Demo results cached and the backup video recorded (human)
- [ ] Limitations and ethics slide ready
