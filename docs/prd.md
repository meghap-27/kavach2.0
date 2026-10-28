ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




  ZeroDay Sentinel – PRDs by Layer and
  Feature Component, with Claude Code Plan
    Oct 28, 2026         · ​@zephyr

  ZeroDay Sentinel is built as five layers, each with named feature components, so work can
  be split between two people and handed to Claude Code one layer at a time.


  1. Layer map

     Layer                            Purpose                                   Feature components          Priority

     L1 Ingestion                     Get code into the                         Zip and GitHub upload,      Must
                                      system                                    snippet scan, diff
                                                                                reader, file filter

     L2 Detection                     Find vulnerable                           Parser and call graph,      Must
                                      paths                                     taint engine, wrapper
                                                                                discovery, rule layer, ML
                                                                                ranker

     L3 Early                         Catch bugs before                         Pre-commit hook, PR         Must (hook, PR
     detection                        merge or before a                         scan (GitHub Action),       scan), Stretch (fix-
                                      CVE                                       incremental cache, fix-     watcher)
                                                                                watcher

     L4 Verification                  Prove findings and                        Proof-of-reachability       Should
     and mitigation                   recommend fixes                           runner, patch suggester,
                                                                                patch re-test,
                                                                                confidence tiers

     L5 Reporting and                 Show, classify, track                     Severity scoring,           Must
     dashboard                                                                  OWASP and CWE
                                                                                tagging, React
                                                                                dashboard, status
                                                                                workflow, PDF, JSON
                                                                                and SARIF export


  One shared finding record connects all five layers. It is defined in layer L2 and used by
  every other layer.



                                                                                                                             Page 1 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




  Part A: Non-technical PRD

  2. Product in one paragraph
  ZeroDay Sentinel is a scanner for Python Flask apps that finds hidden dangerous paths in
  code, including ones that no rule list names. It catches them early (as code is written and
  reviewed), proves they are real with a harmless test, rates their severity, suggests a fix,
  and tracks everything on a dashboard. It answers Hack Fest 2026 PS-01: Zero-Day
  Vulnerability Detection.


  3. Layer by layer, in plain words

  L1 Ingestion: "Bring your code"
       What the user does: uploads a zip, pastes a GitHub link, or pastes one function to test.
       Why it matters: a tool that is hard to start is never used.
       Done when: a project loads in under 30 seconds and unsupported files are skipped
       with a clear message.


  L2 Detection: "Find the hidden risk"
       What it does: follows user input through the code, including through the project's own
       helper functions, and flags the dangerous places it ends up. A small machine learning
       model puts the likely real problems first.
       Why it matters: this is the core claim. It finds risk that rule-based tools miss.
       Done when: it finds all seeded wrapper bugs in the test apps that Bandit and default
       Semgrep miss.


  L3 Early detection: "Catch it before it ships"
       What it does: warns the developer when they commit, comments on pull requests, and
       (as a bonus) watches fixes in the libraries the project uses for patterns that may also
       apply to the project.
       Why it matters: a bug caught at commit costs minutes, a bug caught in production
       costs days.
       Done when: a vulnerable commit is flagged in under 5 seconds, before merge.




                                                                                           Page 2 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




  L4 Verification and mitigation: "Prove it, then fix it"
       What it does: runs a harmless test showing the risk is reachable, suggests a code fix,
       and re-runs the test to confirm the fix works.
       Why it matters: it separates real findings from noise and builds trust.
       Done when: every high-severity finding has a proof result or an honest lower
       confidence label.


  L5 Reporting and dashboard: "See it, rate it, track it"
       What it does: labels each finding with an OWASP category, CWE, and an explainable
       severity score. Shows everything on a dashboard with a status workflow, and exports
       PDF, JSON, and SARIF.
       Why it matters: it meets the problem statement's classification, report, and tracking
       requirements.
       Done when: a judge can open a finding and understand in ten seconds where it is, how
       severe it is, and how to fix it.


  4. Users and value

     User                              Layers they touch                 Value

     Developer                         L3, L4                            Early warning and a ready fix

     Security reviewer                 L2, L4, L5                        Trustworthy, rated, evidence-backed findings

     Hackathon judge                   All                               Live demo, honest numbers, clear claim




  5. Success measures
       Wrapper bugs found that Bandit and default Semgrep miss, shown in a head-to-head
       table.
       Vulnerable commits flagged before merge, with median scan time under 5 seconds.
       False-positive reduction from the ML ranker, measured on projects not used for
       training.
       High-severity findings with a passing proof test.




                                                                                                                        Page 3 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




  6. Honest limits and ethics
         Flask and Python only, three bug classes: command injection, SQL injection, path
         traversal.
         "Zero-day" here means unknown vulnerable paths that no signature covers, not
         undiscovered flaws in code the tool never analyzed.
         The fix-watcher gives leads, not proof.
         Defensive output only. Tests use harmless marker values on our own apps in a sandbox.
         Real issues found in other projects are reported privately to maintainers.

  Part B: Technical PRD

  7. Stack and shared contract
  Stack: Python 3.11, FastAPI, SQLite, Python ast , Semgrep, scikit-learn, Docker, React with
  Vite, pytest.

  Finding record (the contract every layer reads or writes):

     {
       "id": "F-001", "scan_id": "S-01", "file": "app/routes.py", "line": 42,
       "cwe": "CWE-78", "owasp": "A03:2021 Injection",
       "source": "request.args['name']", "sink": "os.system",
       "path": ["download()", "run_report()", "helper()", "os.system"],
       "detector": "taint-wrapper", "ml_rank": 0.87,
       "severity": 8.1, "severity_factors": {},
       "confidence_tier": "pattern-match | reachable | proof-confirmed",
       "fix_suggestion": "", "status": "open | fixed | accepted",
       "introduced_in": "abc123", "detected_at": "write | review | watch",
     "time_to_detect": 0
     }




                                                                                            Page 4 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




  8. Layer specifications

  L1 Ingestion

     Component                   Input                        Output                   Acceptance criteria

     Upload                      Zip or GitHub                Extracted project in a   Rejects files over 50 MB, skips
     handler                     URL                          scan workspace           non-Python, 30 s limit

     Snippet                     Pasted Flask                 Temporary one-file       Works with a missing import
     scanner                     function                     project                  context, falls back gracefully

     Diff reader                 Git diff or                  List of changed files    Maps changed lines to
                                 staged files                 and functions            function names

     File filter                 Project tree                 Python files list        Ignores venv, tests, vendored
                                                                                       code




                                                                                                                   Page 5 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




  L2 Detection

     Component                     Input                        Output                                Acceptance criteria

     Parser and call               Python files                 Functions, calls, route               Resolves intra-project
     graph                                                      map for Flask decorators              calls, flags unresolved
                                                                                                      dynamic calls

     Taint engine                  Call graph                   Source-to-sink paths                  Tracks assignment, string
                                                                                                      formatting, f-strings,
                                                                                                      argument passing; honors
                                                                                                      sanitizers

     Wrapper                       Taint                        Project-specific sinks                Marks functions whose
     discovery                     summaries                                                          parameter reaches a sink
                                                                                                      and propagates upward

     Rule layer                    Files                        Findings for secrets and              Semgrep rules and custom
                                                                weak crypto, plus                     AST checks emit the
                                                                baseline rules                        shared record

     ML ranker                     Findings and                  ml_rank per finding                  Trained on a project-level
                                   features                                                           split, reports false-
                                                                                                      positive reduction


  Sinks in v1: os.system , subprocess with shell, cursor.execute with string-built SQL,
   open and path joins, pickle.loads . Sanitizers: shlex.quote , parameterized queries,
   realpath plus prefix check, secure_filename .


  L3 Early detection

     Component                     Input                                        Output                    Acceptance criteria

     Incremental                   Per-function taint                           Re-analysis of            Diff scan median under
     cache                         summaries                                    changed functions         5 s on the demo repo
                                                                                and callers only

     Pre-commit                    Staged files                                 Terminal findings, exit   Blocks on severity 7 or
     hook                                                                       code                      above, has a bypass
                                                                                                          flag




                                                                                                                                Page 6 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




     Component                     Input                                        Output                    Acceptance criteria

     PR scan                       PR diff                                      Review comments           Comments on the
     (GitHub                                                                    and SARIF upload          exact changed lines
     Action)

     Fix-watcher                   Recent commits of                            New pattern rules         Rule accepted only if it
     (stretch)                     pinned dependencies                          and lead findings         matches the vulnerable
                                                                                                          version and not the
                                                                                                          patched one



  L4 Verification and mitigation

     Component                   Input                           Output                             Acceptance criteria

     Proof runner                Finding and                     Pass or fail, observed             Runs in Docker with no
                                 route                           marker                             network, uses a harmless
                                                                                                    marker value

     Patch                       Finding and                     Diff                               Labeled as a suggestion
     suggester                   code context

     Patch re-test               Patched copy of                 Pass or fail                       Proof fails before and passes
                                 the project                                                        after

     Confidence                  Results above                    confidence_tier                   Unverifiable findings stay
     tiers                                                                                          lower, never dropped



  L5 Reporting and dashboard

     Component                      Input                  Output                             Acceptance criteria

     Severity                       Finding                 severity ,                        Formula below, breakdown
     scoring                        factors                 severity_factors                  shown in the UI

     OWASP and                      Bug class              Labels                             Every finding tagged
     CWE tagging




                                                                                                                                 Page 7 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




     Component                      Input                  Output                           Acceptance criteria

     API (FastAPI)                  Requests               JSON                             Endpoints: POST /scans , GET
                                                                                            /scans/{id} , GET
                                                                                            /scans/{id}/findings , GET
                                                                                            and PATCH /findings/{id} ,
                                                                                            GET /scans/{id}/report , GET
                                                                                            /scans/{id}/sarif , POST
                                                                                            /snippet

     Dashboard                      API                    Pages                            Scan page, findings table with
     (React)                                                                                filters, finding detail with
                                                                                            highlighted path, charts, status
                                                                                            workflow

     Exports                        Findings               PDF, JSON, SARIF                 SARIF validates against the
                                                                                            standard schema


     severity = min(10, base(CWE) + 1.5 * reachable + 1.0 * public_route + 1.0 *
     confidence - 2.0 * sanitizer_present)




  9. Evaluation
       Targets: deliberately vulnerable Flask apps, our own seeded wrapper bugs, and one
       real historical fix from an open-source Python project with identifiers stripped.
       Head-to-head against Bandit and default Semgrep, reporting caught, missed, and
       precision.
       Ablation: rules only, taint only, taint plus ML, taint plus proof.
       Early detection: median diff-scan time and percent of seeded vulnerable commits
       flagged before merge.
       State the small-sample caveat on the results slide.


  10. Technical risks and fixes

     Risk                                                                       Fix

     Dynamic dispatch and framework magic are                                   Flask decorator routes only, stated as a
     missed                                                                     limitation



                                                                                                                           Page 8 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




     Risk                                                                       Fix

     Over-tainting causes false positives                                       Sanitizer list, ML ranker, confidence tiers

     Proof tests are hard to generate for every                                 Confirm a few cases, label the rest honestly
     finding

     Two people collide on integration                                          Shared record, handoff test at hour 10 with
                                                                                fake findings

     Live demo fails                                                            Cache results, run locally, backup video by
                                                                                hour 21



  Part C: Claude Code build plan
  The approach is to build one layer at a time, each ending in a passing test, so Claude Code
  always works from a verified base.


  11. Repo layout
     zeroday-sentinel/
         CLAUDE.md
         docs/prd.md
         backend/
           app/main.py                                    # FastAPI
             app/schema.py                                # finding record (pydantic)
             app/ingest/                                  # L1
         app/detect/                                      # L2: callgraph.py, taint.py, wrappers.py,
     rules.py, ranker.py
             app/early/                                   # L3: incremental.py, hook.py, fixwatch.py
             app/verify/                                  # L4: proof.py, patch.py
             app/report/                                  # L5: severity.py, owasp.py, sarif.py, pdf.py
             tests/
         frontend/                                        # React + Vite
         targets/                                         # seeded vulnerable Flask apps (our own)
         eval/                    # benchmark scripts: bandit, semgrep, ours
         .github/workflows/scan.yml




                                                                                                                              Page 9 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




  12. CLAUDE.md contents
  Put this at the repo root so Claude Code reads it every session:

     # ZeroDay Sentinel
     Flask vulnerability scanner for Hack Fest PS-01. Read docs/prd.md first.


     ## Rules
     - Every layer reads and writes the Finding record in backend/app/schema.py.
     Do not change it without asking.
     - Scope: Python and Flask only. Bug classes: command injection, SQL
     injection, path traversal.
     - Defensive only. Never generate working exploits. Proof tests use harmless
     marker strings, run in Docker with no network, against files in targets/
     only.
     - Write a pytest test for every component before calling it done. Run tests
     after each change.
     - Keep functions small. No new dependencies without asking.


     ## Commands
     - Backend: cd backend && uvicorn app.main:app --reload
     - Tests: cd backend && pytest -q
     - Frontend: cd frontend && npm run dev
     - Eval: python eval/run.py


     ## Build order
     Schema, then L2, L5 API, L1, L3, L4, frontend, eval. See docs/prd.md.




  13. Build order and prompts, by layer
  Paste each prompt into Claude Code in order. Start in plan mode for the first prompt of
  each layer, review the plan, then let it implement. Do not move on until the tests pass.


     Step        Layer               Prompt to give Claude Code                 Done when

     0           Setup               "Read docs/prd.md. Scaffold the repo       pytest runs, schema
                                     layout, a pydantic Finding model           imports
                                     matching the PRD, and a pytest setup. Do
                                     not implement features yet."




                                                                                                      Page 10 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




     Step        Layer               Prompt to give Claude Code                    Done when

     1           Targets             "Create three small intentionally             Ground truth file exists
                                     vulnerable Flask apps in targets/ with
                                     command injection, SQL injection, and
                                     path traversal, where each bug passes
                                     through a custom helper function that
                                     Bandit would not name. Add a ground-
                                     truth JSON listing every seeded bug."

     2           L2                  "Implement callgraph.py and taint.py for      All direct bugs found
                                     Flask routes with the sources, sinks, and
                                     sanitizers in the PRD. Emit Finding
                                     records. Add tests against targets/."

     3           L2                  "Implement wrappers.py: summarize             All seeded wrapper bugs
                                     which function parameters reach a sink        found
                                     and propagate up the call graph. Add
                                     tests proving wrapper bugs in targets/ are
                                     found."

     4           L5                  "Implement severity.py with the formula       Scan returns findings over
                                     in the PRD, owasp.py mapping, and the         HTTP
                                     FastAPI endpoints with SQLite storage.
                                     Add API tests."

     5           L1                  "Implement zip and GitHub URL ingestion,      Upload scans end to end
                                     file filter, and the snippet endpoint with
                                     size and time limits."

     6           Frontend            "Build the React scan page, findings table,   Crude end-to-end by hour
                                     and finding detail with highlighted           14
                                     source-to-sink path and severity
                                     breakdown, using the API."

     7           L3                  "Implement incremental.py with per-           Diff scan under 5 s
                                     function summary caching, a pre-commit
                                     hook script, and a GitHub Action that
                                     scans the PR diff and uploads SARIF."




                                                                                                           Page 11 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




     Step        Layer               Prompt to give Claude Code                   Done when

     8           L4                  "Implement proof.py: for each finding on a   Proof fails before fix,
                                     target, generate a harmless marker           passes after
                                     request, run in Docker with no network,
                                     observe whether the marker reaches the
                                     sink. Then patch.py: suggest a fix, apply
                                     to a copy, re-run. Assign confidence
                                     tiers."

     9           L2                  "Implement ranker.py: features per           Number recorded
                                     finding, train a scikit-learn model with a
                                     split by project, report false-positive
                                     reduction."

     10          Eval                "Write eval/run.py to run Bandit, default    Results table generated
                                     Semgrep, and our scanner on targets/,
                                     output a table of caught, missed, and
                                     precision."

     11          Polish              "Add charts, status workflow, PDF and        Exports open correctly
                                     JSON export, SARIF validation."

     12          Stretch             "Implement fixwatch.py: rank                 Only if on schedule
                                     dependency commits by diff heuristics,
                                     derive a pattern, accept a rule only if it
                                     matches vulnerable and not patched
                                     code."




  14. How to work with Claude Code
          Plan first, then build. Ask for a plan, check it against this PRD, then approve.
          One component per session. Clear the context between layers so it does not drift.
          CLAUDE.md carries the rules.
          Tests are the guard. If a prompt's tests are not passing, ask Claude Code to fix them
          before the next step.
          Commit after each green step so you can roll back.
          Use subagents for independent work. For example, one writes the seeded targets
          while another builds the schema and API, as long as they touch different folders.




                                                                                                            Page 12 of 13
ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan




       Review security-sensitive code yourself. The Docker sandbox and anything that runs
       generated code must be read by a human before use.
       Keep secrets out. API keys in a .env file that is git-ignored.


  15. Schedule for 24 hours (two people)

     Hours          Person A                                                    Person B

     0-2            Steps 0 and 1 together                                      Steps 0 and 1 together

     2-8            Steps 2 and 3 (taint and wrappers)                          Steps 4 and 5 (API and ingestion)

     8-14           Step 8 (proof and patch)                                    Step 6 (frontend), then crude end to end at
                                                                                hour 14

     14-18          Step 7 (early detection), step 9 (ML)                       Step 11 (charts, exports)

     18-21          Step 10 (benchmark), step 12 only if                        Demo polish, cache results, backup video
                    ahead                                                       by hour 21

     21-24          Rehearse and finalize deck                                  Rehearse and finalize deck


  Freeze new features at hour 20. A working layer 2 plus the API and dashboard is a
  complete demo; everything after is a bonus.


  16. Quality checklist before demo
       All seeded wrapper bugs found, and Bandit and Semgrep results recorded for
       comparison
       No false claims: results table states the small sample size
       Vulnerable commit flagged by the hook in under 5 seconds
       Proof test fails before the patch and passes after
       Demo results cached, backup video recorded
       Limitations and ethics slide ready




                                                                                                                       Page 13 of 13
