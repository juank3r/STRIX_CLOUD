from agents.common.findings import STATUS_FAIL, Finding, Report, Severity
from agents.orchestrator import _filter_report, _render


def _mk():
    r = Report(run_id="run1")
    r.add(Finding("C1", "t1", "aws", "r1", "s3_bucket", Severity.HIGH, STATUS_FAIL))
    r.add(Finding("C2", "t2", "gcp", "r2", "gcs_bucket", Severity.LOW, STATUS_FAIL))
    return r


def test_filter_min_severity():
    r = _filter_report(_mk(), min_severity=Severity.HIGH)
    assert len(r.findings) == 1
    assert r.findings[0].provider == "aws"


def test_filter_provider():
    r = _filter_report(_mk(), provider="gcp")
    assert len(r.findings) == 1
    assert r.findings[0].provider == "gcp"


def test_render_all_formats():
    r = _mk()
    assert '"findings"' in _render(r, "json")
    assert "fingerprint" in _render(r, "csv")
    assert "# STRIX_CLOUD findings" in _render(r, "md")
    assert "2.1.0" in _render(r, "sarif")
    assert "STRIX_CLOUD findings" in _render(r, "html")
