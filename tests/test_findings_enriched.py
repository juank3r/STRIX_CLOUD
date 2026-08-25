import csv
import io
import json

from agents.checks import catalog
from agents.common.findings import STATUS_FAIL, STATUS_PASS, Finding, Report, Severity


def _fail(check_id, provider="aws", account="123", resource="r1", sev=Severity.HIGH):
    return Finding(
        check_id=check_id,
        title=f"t-{check_id}",
        provider=provider,
        resource_id=resource,
        resource_type="s3_bucket",
        severity=sev,
        status=STATUS_FAIL,
        account_id=account,
        mitre=["T1530"],
        verification="aws s3api get-bucket-policy-status --bucket r1",
    )


def test_fingerprint_stable_and_scoped():
    a = _fail("C1", account="123", resource="r1")
    b = _fail("C1", account="123", resource="r1")
    c = _fail("C1", account="999", resource="r1")
    assert a.fingerprint == b.fingerprint  # same provider|account|check|resource
    assert a.fingerprint != c.fingerprint  # account changes the fingerprint


def test_finding_to_dict_carries_enrichment():
    d = _fail("C1").to_dict()
    assert d["mitre"] == ["T1530"]
    assert d["account_id"] == "123"
    assert d["verification"].startswith("aws s3api")
    assert d["fingerprint"]


def test_report_metadata_and_grouping():
    r = Report(run_id="run1", operator="alice", started_at="2026-01-01T00:00:00Z")
    r.add(_fail("C1", account="123"))
    r.add(_fail("C2", account="456"))
    assert set(r.by_account().keys()) == {"123", "456"}
    data = json.loads(r.to_json())
    assert data["run"]["run_id"] == "run1"
    assert data["run"]["operator"] == "alice"


def test_deduplicate_by_fingerprint():
    r = Report()
    r.add(_fail("C1", account="123", resource="r1"))
    r.add(_fail("C1", account="123", resource="r1"))  # duplicate
    r.add(_fail("C1", account="123", resource="r2"))
    assert len(r.findings) == 3
    assert len(r.deduplicate().findings) == 2


def test_markdown_contains_verification_and_mitre():
    r = Report(run_id="run1")
    r.add(_fail("C1"))
    md = r.to_markdown()
    assert "ATT&CK T1530" in md
    assert "Verify:" in md
    assert "aws s3api" in md


def test_csv_has_header_and_row():
    r = Report()
    r.add(_fail("C1"))
    rows = list(csv.reader(io.StringIO(r.to_csv())))
    assert rows[0][0] == "fingerprint"
    assert "T1530" in rows[1]  # mitre column


def test_catalog_control_injects_mitre():
    f = catalog.STORAGE_PUBLIC_ACCESS.finding("aws", "b", "s3_bucket", status=STATUS_PASS)
    assert "T1530" in f.mitre
