from agents.common.findings import STATUS_FAIL, Finding, Report, Severity
from agents.report.html import render_html


def _report():
    r = Report(run_id="run1", operator="alice")
    r.add(
        Finding(
            check_id="EXPOSURE_INSTANCE_ADMIN_PORT",
            title="Live instance exposed",
            provider="aws",
            resource_id="<script>alert(1)</script>",
            resource_type="ec2_instance",
            severity=Severity.CRITICAL,
            status=STATUS_FAIL,
            account_id="123",
            mitre=["T1190"],
            verification="aws ec2 describe-instances --instance-ids i-1",
        )
    )
    return r


def test_html_contains_findings_and_meta():
    html = render_html(_report())
    assert "STRIX_CLOUD findings" in html
    assert "run1" in html
    assert "T1190" in html
    assert "aws ec2 describe-instances" in html
    assert 'class="copy"' in html  # one-click verify copy


def test_html_escapes_malicious_resource_name():
    html = render_html(_report())
    # The raw payload must never appear unescaped in the report.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_empty_report():
    html = render_html(Report())
    assert "No failing findings" in html
