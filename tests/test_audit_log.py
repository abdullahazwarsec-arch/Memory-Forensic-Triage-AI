"""HMAC-chained audit log: tamper detection, single writer, concurrency, archiving."""
import importlib
import logging
import subprocess
import sys

import pytest

from memtriage import audit_log


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "audit.log"
    path.write_bytes(b"legacy line one\r\nlegacy line two\r\n")
    logger = logging.getLogger("triage.test")
    handler = audit_log.ChainedFileHandler(str(path))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for i in range(6):
        logger.info(f"event {i}")
    logger.info("evil\n2026-01-01 00:00:00 | INFO | FORGED LINE")
    yield path
    logger.removeHandler(handler)


def tampered(path, data: bytes) -> bool:
    original, head = path.read_bytes(), (path.parent / (path.name + ".head")).read_bytes()
    path.write_bytes(data)
    broken = not audit_log.verify_log(str(path))["verified"]
    path.write_bytes(original)
    (path.parent / (path.name + ".head")).write_bytes(head)
    return broken


def test_chain_verifies_and_anchors_legacy_lines(log):
    result = audit_log.verify_log(str(log))
    assert result["verified"] and result["legacy_lines"] == 2 and result["chained_lines"] == 8


def test_newline_injection_cannot_forge_a_line(log):
    lines = log.read_text(encoding="utf-8").splitlines()
    assert not any(line.startswith("2026-01-01 00:00:00 | INFO | FORGED") for line in lines)


def test_tampering_is_detected(log):
    data = log.read_bytes()
    lines = data.split(b"\n")
    assert tampered(log, data.replace(b"event 2", b"event 9"))                 # edited
    assert tampered(log, data.replace(b"legacy line one", b"legacy line 1!"))  # legacy edited
    assert tampered(log, b"\n".join(lines[:5] + lines[6:]))                    # line removed
    assert tampered(log, b"\n".join(lines[:-3]) + b"\n")                      # tail truncated
    assert tampered(log, data + b"2026 | INFO | sneaky\n")                    # unchained append
    assert audit_log.verify_log(str(log))["verified"]


def test_duplicate_lines_are_diagnosed(log):
    lines = log.read_bytes().split(b"\n")
    duplicated = b"\n".join(lines[:5] + [lines[4]] + lines[5:])
    log.write_bytes(duplicated)
    problems = audit_log.verify_log(str(log))["problems"]
    assert any("duplicate of line" in p for p in problems)


def test_module_reload_leaves_a_single_writer(tmp_path):
    path = str(tmp_path / "reload.log")
    global audit_log
    for _ in range(3):
        audit_log.setup(path)
        audit_log = importlib.reload(audit_log)
    audit_log.setup(path)
    app_logger = logging.getLogger("triage")
    writers = [h for h in app_logger.handlers if type(h).__name__ == "ChainedFileHandler"]
    try:
        assert len(writers) == 1
        app_logger.info("written once")
        assert sum("written once" in l for l in open(path, encoding="utf-8")) == 1
        logging.getLogger("asyncio").error("library noise")
        assert "library noise" not in open(path, encoding="utf-8").read()
    finally:
        for h in writers:
            app_logger.removeHandler(h)


def test_concurrent_processes_keep_one_valid_chain(tmp_path, root):
    path = str(tmp_path / "multi.log")
    code = ("import sys,logging; sys.path.insert(0, r'%s'); from memtriage import audit_log; "
            "audit_log.setup(r'%s'); lg=logging.getLogger('triage'); "
            "[lg.info('proc %%s line %%d' %% (sys.argv[1], i)) for i in range(25)]") % (root, path)
    procs = [subprocess.Popen([sys.executable, "-c", code, str(n)]) for n in range(4)]
    assert all(p.wait() == 0 for p in procs)
    assert sum(" proc " in l for l in open(path, encoding="utf-8")) == 100
    assert audit_log.verify_log(path)["verified"]


def test_archive_and_restart(log):
    report = audit_log.archive_and_restart(str(log), "Test archive of a log with a broken chain", by="tester")
    assert (log.parent / "archive" / report["archived_log"]).is_file()
    assert audit_log.verify_log(str(log))["verified"]
    assert report["sha256"] in log.read_text(encoding="utf-8")
    archives = audit_log.list_archives(str(log))
    assert len(archives) == 1 and archives[0]["unchanged_since_archive"]
    with pytest.raises(ValueError):
        audit_log.archive_and_restart(str(log), "short", by="x")
