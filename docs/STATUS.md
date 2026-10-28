# Status

Current step: **2, L2 taint** (next)
Hackathon clock start: _set at kickoff_

| # | Step | State | Gate evidence | Commit | Notes / deviations |
|---|---|---|---|---|---|
| 0 | Setup | done | `pytest -q`: 3 passed; schema imports | step-0 | Python 3.13 in build env (PRD says 3.11; compatible) |
| 1 | Targets | done | `pytest -q`: 8 passed; 12 positives (6 direct, 6 wrapper), 6 negatives (3 sanitized, 3 dead code) | step-1 | Sinks added beyond PRD list: os.popen, send_file, shutil.copy, os.remove, executescript (see D9) |
| 2 | L2 taint | todo | | | |
| 3 | L2 wrappers | todo | | | |
| 4 | Eval harness | todo | | | |
| 5 | L5 severity + API | todo | | | |
| 6 | L1 ingestion | todo | | | |
| 7 | Frontend | todo | | | |
| 8 | L3 early detection | todo | | | |
| 9 | L4 proof + patch | todo | | | human review of app/verify/ required |
| 10 | ML ranker | todo | | | |
| 11 | Polish | todo | | | freeze at hour 20 |
| 12 | Stretch: fix-watcher | todo | | | only if ahead |

## Early finding: Bandit baseline (preview before step 4)
Bandit flags command-injection sinks by pattern (`os.system`, `shell=True`) wherever they appear, including inside helpers. On the seeded targets it hits CMD-W1, CMD-W2 and SQL-W2 by line, but it also flags all three sanitized/dead-code negatives in the cmd and sqli apps, and it finds nothing for path traversal.
**Implication:** the claim must be "more wrapper bugs found, with a source-to-sink path, at higher precision", not "every wrapper bug Bandit misses". Step 4 measures this properly.

## Known limitations (for the slide)
- Python and Flask only; decorator routes only; dynamic dispatch is not resolved.
- Three bug classes: CWE-78, CWE-89, CWE-22.
- Small evaluation sample; numbers are indicative.
- Fix-watcher output is leads, not proof.
