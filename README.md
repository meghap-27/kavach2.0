# Kavach 2.0 — ZeroDay Sentinel

Flask vulnerability scanner that finds source-to-sink paths through a project's own helper functions, catches them at commit and review time, proves them with harmless markers, and tracks them on a dashboard. Built for Hack Fest 2026 PS-01.

- PRD: `docs/prd.md`, amendments: `docs/decisions.md`
- Build plan: `docs/build-plan.md`, progress: `docs/STATUS.md`

```bash
cd backend && pip install -r requirements.txt && pytest -q
```
