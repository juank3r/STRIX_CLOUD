from agents.common.findings import STATUS_FAIL, Finding, Report, Severity
from agents.report import narrative


def _report():
    r = Report(run_id="r1")
    r.add(
        Finding(
            "EXPOSURE_INSTANCE_ADMIN_PORT", "Exposed", "aws", "i-1", "ec2_instance",
            Severity.CRITICAL, STATUS_FAIL, account_id="123",
            evidence={"public_ip": "1.2.3.4", "open_admin_ports": [22]},
        )
    )
    r.add(
        Finding(
            "IAM_ADMIN_PRINCIPAL", "Admin", "aws", "admin-role", "iam_role",
            Severity.HIGH, STATUS_FAIL, account_id="123",
        )
    )
    r.add(
        Finding(
            "STORAGE_PUBLIC_ACCESS", "Public", "aws", "prod-bucket", "s3_bucket",
            Severity.HIGH, STATUS_FAIL, account_id="123",
        )
    )
    return r


def test_describe_exposure_mentions_ip_and_port():
    exposure = [f for f in _report().failures() if f.check_id == "EXPOSURE_INSTANCE_ADMIN_PORT"][0]
    s = narrative.describe(exposure)
    assert "1.2.3.4" in s and "22" in s


def test_attack_chain_correlates_exposure_and_admin():
    chains = narrative.attack_chains(_report())
    assert len(chains) == 1
    assert "account 123" in chains[0]["title"]
    assert len(chains[0]["steps"]) == 3


def test_top_findings_ranks_exposure_first():
    top = narrative.top_findings(_report())
    assert top[0].check_id == "EXPOSURE_INSTANCE_ADMIN_PORT"


def test_start_here_puts_chain_first_and_dedups():
    sh = narrative.start_here(_report())
    assert sh[0]["kind"] == "chain"
    kinds = [i["kind"] for i in sh]
    assert "finding" in kinds  # the public bucket still surfaces standalone


def test_targets_text_lists_host_bucket_admin():
    txt = narrative.targets_text(_report())
    assert "1.2.3.4" in txt
    assert "prod-bucket" in txt
    assert "admin-role" in txt
