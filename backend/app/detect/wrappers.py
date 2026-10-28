"""Wrapper discovery (L2): per-function taint summaries composed to a fixpoint.

A function whose parameter reaches a sink unsanitized becomes a project-specific
sink. Callers that pass their own parameters into it inherit the summary, so a route
three helpers away from `os.system` is still connected to it.
"""
from .callgraph import Project, callers_of
from .taint import FunctionAnalyzer, RawHit, SinkHit, Summary

MAX_ITERS = 20


def compute_summaries(project: Project) -> dict[str, Summary]:
    summaries = {q: Summary() for q in project.functions}
    for _ in range(MAX_ITERS):
        changed = False
        for q, fn in project.functions.items():
            new = FunctionAnalyzer(project, fn, summaries).run().summary()
            if new != summaries[q]:
                summaries[q], changed = new, True
        if not changed:
            break
    return summaries


def reachable_from_routes(project: Project) -> set[str]:
    callees: dict[str, set[str]] = {q: set() for q in project.functions}
    for callee, callers in callers_of(project).items():
        for c in callers:
            callees[c].add(callee)
    seen = {q for q, f in project.functions.items() if f.route}
    stack = list(seen)
    while stack:
        for nxt in callees[stack.pop()]:
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def source_hits(project: Project, summaries: dict[str, Summary]) -> set[RawHit]:
    hits: set[RawHit] = set()
    for fn in project.functions.values():
        hits |= FunctionAnalyzer(project, fn, summaries).run().hits
    return hits


def orphan_wrappers(project: Project, summaries: dict[str, Summary]) -> list[tuple[str, SinkHit]]:
    """Sink-reaching functions that nothing calls and no route exposes."""
    callers = callers_of(project)
    out = []
    for q, fn in project.functions.items():
        if fn.route or callers[q]:
            continue
        out += [(q, hit) for hit in summaries[q].sinks]
    return out
