import pytest
from pydantic import ValidationError

from app.schema import Finding

SAMPLE = {
    "id": "F-001", "scan_id": "S-01", "file": "app/routes.py", "line": 42,
    "cwe": "CWE-78", "owasp": "A03:2021 Injection",
    "source": "request.args['name']", "sink": "os.system",
    "path": ["download()", "run_report()", "helper()", "os.system"],
    "detector": "taint-wrapper", "ml_rank": 0.87,
    "severity": 8.1, "severity_factors": {"base": 6.0},
    "confidence_tier": "reachable", "fix_suggestion": "", "status": "open",
    "introduced_in": "abc123", "detected_at": "write", "time_to_detect": 0,
}


def test_round_trip():
    f = Finding(**SAMPLE)
    assert Finding.model_validate_json(f.model_dump_json()) == f


def test_rejects_bad_tier():
    with pytest.raises(ValidationError):
        Finding(**{**SAMPLE, "confidence_tier": "maybe"})


def test_rejects_bad_status():
    with pytest.raises(ValidationError):
        Finding(**{**SAMPLE, "status": "wontfix"})
