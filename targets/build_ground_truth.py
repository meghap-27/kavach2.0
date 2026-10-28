"""Builds targets/ground_truth.json.

Labels (kind, CWE, sink, expected path) are written by hand below. Line numbers are
read from the `# ZDS:<id>` tag on the sink line, so edits to the apps can't make the
ground truth drift. Run: python targets/build_ground_truth.py
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent
TAG = re.compile(r"#\s*ZDS:([A-Z]+-[A-Z]\d)")

LABELS = {
    # command injection
    "CMD-D1": ("direct", "CWE-78", "os.system", ["ping()", "os.system"]),
    "CMD-D2": ("direct", "CWE-78", "subprocess.check_output", ["lookup()", "subprocess.check_output"]),
    "CMD-W1": ("wrapper", "CWE-78", "subprocess.run", ["report()", "build_report()", "_render()", "_run_task()", "subprocess.run"]),
    "CMD-W2": ("wrapper", "CWE-78", "os.popen", ["archive()", "archive_logs()", "_compress()", "os.popen"]),
    "CMD-N1": ("negative-sanitized", "CWE-78", "os.system", []),
    "CMD-N2": ("negative-deadcode", "CWE-78", "os.system", []),
    # SQL injection
    "SQL-D1": ("direct", "CWE-89", "cursor.execute", ["user()", "cursor.execute"]),
    "SQL-D2": ("direct", "CWE-89", "cursor.execute", ["order()", "cursor.execute"]),
    "SQL-W1": ("wrapper", "CWE-89", "cursor.execute", ["profile()", "find_user_by()", "_fetch()", "cursor.execute"]),
    "SQL-W2": ("wrapper", "CWE-89", "cursor.executescript", ["search()", "search_items()", "_like_clause()", "cursor.executescript"]),
    "SQL-N1": ("negative-sanitized", "CWE-89", "cursor.execute", []),
    "SQL-N2": ("negative-deadcode", "CWE-89", "connection.execute", []),
    # path traversal
    "PATH-D1": ("direct", "CWE-22", "open", ["download()", "open"]),
    "PATH-D2": ("direct", "CWE-22", "send_file", ["avatar()", "send_file"]),
    "PATH-W1": ("wrapper", "CWE-22", "open", ["note()", "read_note()", "_resolve()", "_load()", "open"]),
    "PATH-W2": ("wrapper", "CWE-22", "shutil.copy", ["export()", "export_attachment()", "_resolve()", "shutil.copy"]),
    "PATH-N1": ("negative-sanitized", "CWE-22", "open", []),
    "PATH-N2": ("negative-deadcode", "CWE-22", "os.remove", []),
}


def find_tags() -> dict[str, tuple[str, int]]:
    tags = {}
    for py in sorted(ROOT.glob("*_app/*.py")):
        for no, text in enumerate(py.read_text().splitlines(), start=1):
            m = TAG.search(text)
            if m:
                tags[m.group(1)] = (str(py.relative_to(ROOT)), no)
    return tags


def build() -> list[dict]:
    tags = find_tags()
    missing = set(LABELS) ^ set(tags)
    if missing:
        raise SystemExit(f"tags and labels disagree: {sorted(missing)}")
    rows = []
    for bug_id, (kind, cwe, sink, path) in LABELS.items():
        file, line = tags[bug_id]
        rows.append({"id": bug_id, "file": file, "line": line, "cwe": cwe,
                     "kind": kind, "sink": sink, "expected_path": path})
    return rows


if __name__ == "__main__":
    out = ROOT / "ground_truth.json"
    out.write_text(json.dumps(build(), indent=2) + "\n")
    print(f"wrote {out} ({len(LABELS)} entries)")
