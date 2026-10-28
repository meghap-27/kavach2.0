"""Run L2 detection on a project and return shared Finding records."""
from pathlib import Path

from ..schema import Finding
from .callgraph import Project, build_project
from .taint import RawHit, SinkHit
from .wrappers import compute_summaries, orphan_wrappers, reachable_from_routes, source_hits


def _detector(path: tuple[str, ...]) -> str:
    return "taint-direct" if len(path) <= 2 else "taint-wrapper"


def _from_hit(hit: RawHit, reachable: set[str], scan_id: str) -> Finding:
    return Finding(
        id="", scan_id=scan_id, file=hit.file, line=hit.line, cwe=hit.cwe,
        source=hit.source, sink=hit.sink, path=list(hit.path), detector=_detector(hit.path),
        confidence_tier="reachable" if hit.function in reachable else "pattern-match",
    )


def _from_orphan(qualname: str, hit: SinkHit, scan_id: str) -> Finding:
    return Finding(
        id="", scan_id=scan_id, file=hit.file, line=hit.line, cwe=hit.cwe,
        source=f"parameter '{hit.param}' of {qualname.split(':')[1]}() (no route calls it)",
        sink=hit.sink, path=list(hit.path), detector="taint-unreachable",
        confidence_tier="pattern-match",
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (file, line, cwe); keep the shortest path, merge sources."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.file, f.line, f.cwe)
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        sources = sorted(set(cur.source.split(" | ")) | {f.source})
        rank = {"pattern-match": 0, "reachable": 1, "proof-confirmed": 2}
        better = (rank[f.confidence_tier], -len(f.path)) > (rank[cur.confidence_tier], -len(cur.path))
        keep = f if better else cur
        best[key] = keep.model_copy(update={"source": " | ".join(sources)})
    return list(best.values())


def scan_project(root: str | Path, scan_id: str = "S-local", files: list[Path] | None = None,
                 project: Project | None = None) -> list[Finding]:
    project = project or build_project(root, files)
    summaries = compute_summaries(project)
    reachable = reachable_from_routes(project)
    found = [_from_hit(h, reachable, scan_id) for h in source_hits(project, summaries)]
    covered = {(f.file, f.line, f.cwe) for f in found}
    found += [_from_orphan(q, h, scan_id) for q, h in orphan_wrappers(project, summaries)
              if (h.file, h.line, h.cwe) not in covered]
    found = sorted(_dedupe(found), key=lambda f: (f.file, f.line, f.cwe))
    return [f.model_copy(update={"id": f"F-{i:03d}"}) for i, f in enumerate(found, 1)]
