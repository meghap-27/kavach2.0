"""Steps 2 and 3 gates: detection scored against targets/ground_truth.json."""
import json
from pathlib import Path

import pytest

from app.detect.callgraph import build_project
from app.detect.scanner import scan_project

TARGETS = Path(__file__).resolve().parents[2] / "targets"
GT = json.loads((TARGETS / "ground_truth.json").read_text())
APPS = ("cmd_app", "sqli_app", "path_app")


@pytest.fixture(scope="module")
def findings():
    out = {}
    for app in APPS:
        for f in scan_project(TARGETS / app, scan_id=app):
            out[(f"{app}/{f.file}", f.line, f.cwe)] = f
    return out


def _rows(kind):
    return [r for r in GT if r["kind"] == kind]


def _key(row):
    return (row["file"], row["line"], row["cwe"])


# ---- step 2 gate ----------------------------------------------------------
@pytest.mark.parametrize("row", _rows("direct"), ids=lambda r: r["id"])
def test_direct_bug_found(findings, row):
    f = findings.get(_key(row))
    assert f is not None, f"missed {row['id']}"
    assert f.detector == "taint-direct"
    assert f.confidence_tier == "reachable"
    assert f.path[-1] == row["sink"].replace("connection.", "cursor.")


@pytest.mark.parametrize("row", _rows("negative-sanitized"), ids=lambda r: r["id"])
def test_sanitized_not_flagged(findings, row):
    assert _key(row) not in findings


# ---- step 3 gate ----------------------------------------------------------
@pytest.mark.parametrize("row", _rows("wrapper"), ids=lambda r: r["id"])
def test_wrapper_bug_found(findings, row):
    f = findings.get(_key(row))
    assert f is not None, f"missed {row['id']}"
    assert f.detector == "taint-wrapper"
    assert f.confidence_tier == "reachable"
    assert f.path[0] == row["expected_path"][0]  # starts at the route
    assert f.path[-1] == row["sink"]


@pytest.mark.parametrize("row", _rows("negative-deadcode"), ids=lambda r: r["id"])
def test_deadcode_never_reachable(findings, row):
    f = findings.get(_key(row))
    assert f is None or (f.confidence_tier == "pattern-match" and f.detector == "taint-unreachable")


def test_no_unexpected_reachable_findings(findings):
    expected = {_key(r) for r in GT if r["kind"] in ("direct", "wrapper")}
    extra = [k for k, f in findings.items() if f.confidence_tier != "pattern-match" and k not in expected]
    assert extra == []


# ---- unit checks on the engine --------------------------------------------
def _scan_src(tmp_path, src, extra=None):
    (tmp_path / "app.py").write_text(src)
    for name, text in (extra or {}).items():
        (tmp_path / name).write_text(text)
    return scan_project(tmp_path)


HEADER = "import os, shlex, subprocess\nfrom flask import Flask, request\napp = Flask(__name__)\n"


def test_quote_only_sanitizes_command_injection(tmp_path):
    src = HEADER + (
        "@app.route('/a')\ndef a():\n    x = shlex.quote(request.args['f'])\n"
        "    open('/srv/' + x)\n    os.system('ls ' + x)\n")
    found = _scan_src(tmp_path, src)
    assert [f.cwe for f in found] == ["CWE-22"]


def test_shell_false_not_flagged(tmp_path):
    src = HEADER + "@app.route('/a')\ndef a():\n    subprocess.run(['ls', request.args['d']])\n"
    assert _scan_src(tmp_path, src) == []


def test_reassignment_kills_taint(tmp_path):
    src = HEADER + "@app.route('/a')\ndef a():\n    x = request.args['d']\n    x = 'safe'\n    os.system(x)\n"
    assert _scan_src(tmp_path, src) == []


def test_branch_merge_keeps_taint(tmp_path):
    src = HEADER + ("@app.route('/a')\ndef a():\n    x = 'safe'\n    if request.args:\n"
                    "        x = request.args['d']\n    os.system(x)\n")
    assert len(_scan_src(tmp_path, src)) == 1


def test_keyword_argument_into_wrapper(tmp_path):
    helpers = "import os\ndef run(cmd=''):\n    os.system(cmd)\n"
    src = HEADER + "from helpers import run\n@app.route('/a')\ndef a():\n    run(cmd=request.form['c'])\n"
    found = _scan_src(tmp_path, src, {"helpers.py": helpers})
    assert [f.path for f in found] == [["a()", "run()", "os.system"]]


def test_recursion_terminates(tmp_path):
    src = HEADER + ("def loop(x, n):\n    if n:\n        return loop(x, n - 1)\n    os.system(x)\n"
                    "@app.route('/a')\ndef a():\n    loop(request.args['c'], 3)\n")
    found = _scan_src(tmp_path, src)
    assert any(f.path[0] == "a()" for f in found)


def test_dynamic_calls_recorded(tmp_path):
    (tmp_path / "app.py").write_text("import os\ndef f(n):\n    getattr(os, n)('x')\n")
    assert build_project(tmp_path).unresolved
