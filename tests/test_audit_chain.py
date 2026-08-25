import json

from agents.common import audit


def _read_entries(path):
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def test_audit_chain_intact_and_tamper_evident(tmp_path):
    log = tmp_path / "audit.log"
    handler = audit.configure_file_audit(str(log))
    try:
        audit.reset_chain()
        audit.audit("a.one", {"x": 1})
        audit.audit("a.two", {"x": 2})
        handler.flush()

        entries = _read_entries(log)
        assert len(entries) >= 2
        assert entries[0]["seq"] == 0
        assert entries[0]["prev"] == audit.GENESIS
        assert entries[1]["prev"] == entries[0]["hash"]
        assert audit.verify_chain(entries) is True

        # Tampering with a past entry breaks the chain.
        tampered = [dict(e) for e in entries]
        tampered[0]["details"] = {"x": 999}
        assert audit.verify_chain(tampered) is False
    finally:
        audit.logger.removeHandler(handler)
        handler.close()
