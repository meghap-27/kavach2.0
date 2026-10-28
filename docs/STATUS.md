# Status

Current step: **1, Targets** (next)
Hackathon clock start: _set at kickoff_

| # | Step | State | Gate evidence | Commit | Notes / deviations |
|---|---|---|---|---|---|
| 0 | Setup | done | `pytest -q`: 3 passed; schema imports | step-0 | Python 3.13 in build env (PRD says 3.11; compatible). Not yet pushed: GitHub not linked |
| 1 | Targets | todo | | | |
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

## Known limitations (for the slide)
- Python and Flask only; decorator routes only; dynamic dispatch is not resolved.
- Three bug classes: CWE-78, CWE-89, CWE-22.
- Small evaluation sample; numbers are indicative.
- Fix-watcher output is leads, not proof.
