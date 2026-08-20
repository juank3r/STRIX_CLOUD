import json

from agents.common import audit


def test_configure_file_audit_writes_json_lines(tmp_path):
    log = tmp_path / "audit.log"
    handler = audit.configure_file_audit(str(log))
    try:
        assert handler is not None
        # Idempotent for the same path.
        assert audit.configure_file_audit(str(log)) is handler

        audit.audit("test.event", {"k": "v", "n": 1})
        handler.flush()

        lines = log.read_text(encoding="utf-8").strip().splitlines()
        assert lines
        entry = json.loads(lines[-1])
        assert entry["event"] == "test.event"
        assert entry["details"]["k"] == "v"
        assert "ts" in entry
    finally:
        # Detach so later tests don't write to the (soon deleted) tmp file.
        audit.logger.removeHandler(handler)
        handler.close()


def test_no_file_handler_without_path(monkeypatch):
    monkeypatch.delenv("STRIX_AUDIT_LOG", raising=False)
    assert audit.configure_file_audit(None) is None
