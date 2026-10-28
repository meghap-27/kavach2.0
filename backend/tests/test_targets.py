"""Step 1 gate: ground truth matches the seeded target apps."""
import ast
import json
from pathlib import Path

TARGETS = Path(__file__).resolve().parents[2] / "targets"
GT = json.loads((TARGETS / "ground_truth.json").read_text())


def _line(row):
    return (TARGETS / row["file"]).read_text().splitlines()[row["line"] - 1]


def test_counts():
    positives = [r for r in GT if r["kind"] in ("direct", "wrapper")]
    negatives = [r for r in GT if r["kind"].startswith("negative")]
    assert len(positives) >= 12
    assert len(negatives) >= 6
    for app in ("cmd_app", "sqli_app", "path_app"):
        kinds = [r["kind"] for r in GT if r["file"].startswith(app)]
        assert kinds.count("direct") == 2 and kinds.count("wrapper") == 2
        assert "negative-sanitized" in kinds and "negative-deadcode" in kinds


def test_lines_hold_tag_and_sink():
    for row in GT:
        text = _line(row)
        assert f"ZDS:{row['id']}" in text, row["id"]
        sink_call = row["sink"].split(".")[-1] + "("
        assert sink_call in text, (row["id"], text)


def test_ground_truth_is_current():
    import importlib.util
    spec = importlib.util.spec_from_file_location("bgt", TARGETS / "build_ground_truth.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.build() == GT


def test_targets_parse():
    for py in TARGETS.glob("*_app/*.py"):
        ast.parse(py.read_text())


def test_wrapper_paths_have_helpers():
    for row in GT:
        if row["kind"] == "wrapper":
            assert len(row["expected_path"]) >= 3
