import json

import pytest

from agents.checks import catalog
from agents.common.findings import STATUS_FAIL, STATUS_PASS, Finding, Report, Severity


def test_severity_ordering_and_from_name():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.from_name("high") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.from_name("bogus")


def test_finding_validation_and_normalization():
    f = Finding(
        check_id="X",
        title="t",
        provider="aws",
        resource_id="r",
        resource_type="s3_bucket",
        severity="HIGH",  # string is normalized to the enum
        status=STATUS_FAIL,
    )
    assert f.severity is Severity.HIGH
    assert f.is_failure is True
    with pytest.raises(ValueError):
        Finding(
            check_id="X",
            title="t",
            provider="aws",
            resource_id="r",
            resource_type="s3_bucket",
            severity=Severity.LOW,
            status="not-a-status",
        )


def _sample_report():
    report = Report()
    report.add(catalog.STORAGE_PUBLIC_ACCESS.finding("aws", "b1", "s3_bucket", status=STATUS_FAIL))
    report.add(catalog.STORAGE_VERSIONING.finding("aws", "b1", "s3_bucket", status=STATUS_FAIL))
    report.add(catalog.STORAGE_ENCRYPTION.finding("gcp", "b2", "gcs_bucket", status=STATUS_PASS))
    return report


def test_report_summary_and_highest_severity():
    report = _sample_report()
    summary = report.summary()
    assert summary["total"] == 3
    assert summary["failures"] == 2
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["LOW"] == 1
    assert report.highest_severity() is Severity.HIGH
    assert len(report.failures()) == 2


def test_report_json_roundtrip():
    report = _sample_report()
    data = json.loads(report.to_json())
    assert data["summary"]["failures"] == 2
    assert len(data["findings"]) == 3
    only = json.loads(report.to_json(failures_only=True))
    assert len(only["findings"]) == 2


def test_report_sarif_structure():
    report = _sample_report()
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    # Only failures become SARIF results.
    assert len(run["results"]) == 2
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "STORAGE_PUBLIC_ACCESS" in rule_ids
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels  # HIGH -> error
