"""
Tamper-Evident Audit Log
========================
Every line written to logs/triage_audit.log ends with
    | CHAIN=<HMAC-SHA256(ledger key, previous CHAIN + "\\n" + line)>
so editing, inserting, deleting or reordering any line breaks the chain. The
first chained line ("AUDIT LOG CHAIN GENESIS") records the size and SHA-256 of
the unchained history written before chaining was enabled, so that history is
anchored as well.

Deleting lines from the end cannot be seen in the chain itself, so a keyed
"head" file (<log>.head) stores the line count and last CHAIN value; a log
that is shorter than its head is reported as truncated.

Line breaks in messages are escaped, so a crafted value (file name, notes...)
cannot forge an extra log line.

Every write happens under a cross-process file lock and takes the previous
CHAIN value from the file itself (not from memory), so several writers - e.g.
two dashboard processes, or a module reloaded by Streamlit - can never fork
the chain. Only one handler is ever attached per log file.

A log whose chain is broken cannot be honestly re-sealed. Instead it is
archived unchanged (logs/archive/) with a verification report, and a new
chain starts whose genesis line records the archived file's SHA-256.

Command line:
    python -m memtriage.audit_log verify [logs/triage_audit.log]
    python -m memtriage.audit_log archive --reason "<why>" [logs/triage_audit.log]
"""

import os
import re
import sys
import hmac
import json
import time
import getpass
import hashlib
import logging
from datetime import datetime

from . import evidence_integrity as ei


CHAIN_SEP   = " | CHAIN="
GENESIS_MSG = "AUDIT LOG CHAIN GENESIS"
HANDLER_TAG = "_memtriage_chained_log"   # survives module reloads (isinstance does not)
LOGGER_NAME = "triage"                    # only the app's own events are audited
LOG_FORMAT  = "%(asctime)s | %(levelname)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _mac(key: bytes, prev: str, line: str) -> str:
    return hmac.new(key, f"{prev}\n{line}".encode("utf-8"), hashlib.sha256).hexdigest()


def _head_mac(key: bytes, count: int, last: str) -> str:
    return hmac.new(key, f"head|{count}|{last}".encode("utf-8"), hashlib.sha256).hexdigest()


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def _split_lines(data: bytes) -> list:
    """Split raw log bytes into (start_offset, line_text) tuples."""
    lines, pos = [], 0
    for raw in data.split(b"\n"):
        end = pos + len(raw) + 1
        if raw.strip(b"\r"):
            lines.append((pos, raw.rstrip(b"\r").decode("utf-8", errors="replace")))
        pos = end
    return lines


class _FileLock:
    """Exclusive cross-process lock on <log>.lock (msvcrt on Windows, fcntl elsewhere)."""

    def __init__(self, path: str):
        self.path = f"{path}.lock"

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.f = open(self.path, "a+b")
        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    self.f.seek(0)
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_LOCK, 1)
                    return self
                except OSError:
                    time.sleep(0.05)
        import fcntl
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f, fcntl.LOCK_UN)
        finally:
            self.f.close()


def _format(message: str) -> str:
    return logging.Formatter(LOG_FORMAT, DATE_FORMAT).format(
        logging.LogRecord(LOGGER_NAME, logging.INFO, __file__, 0, message, None, None))


def _last_chain(path: str):
    """Last CHAIN value in the file (read from the tail), or None if nothing is chained."""
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - 65536))
        tail = f.read()
    for _, text in reversed(_split_lines(tail)):
        if CHAIN_SEP in text:
            return text.rsplit(CHAIN_SEP, 1)[1].strip()
    if size > 65536:   # very long unchained tail: fall back to a full scan
        with open(path, "rb") as f:
            chained = [t for _, t in _split_lines(f.read()) if CHAIN_SEP in t]
        return chained[-1].rsplit(CHAIN_SEP, 1)[1].strip() if chained else None
    return None


def _read_head(path: str, key: bytes):
    try:
        with open(f"{path}.head", "r", encoding="utf-8") as f:
            count, last, mac = f.read().split()
        if count.isdigit() and hmac.compare_digest(_head_mac(key, int(count), last), mac):
            return int(count), last
    except (OSError, ValueError):
        pass
    return None


def _write_line(path: str, key: bytes, prev: str, count: int, line: str) -> str:
    line = _escape(line)
    mac = _mac(key, prev, line)
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(f"{line}{CHAIN_SEP}{mac}\n")
    tmp = f"{path}.head.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(f"{count + 1} {mac} {_head_mac(key, count + 1, mac)}\n")
    os.replace(tmp, f"{path}.head")
    return mac


def _write_genesis(path: str, key: bytes, **extra) -> str:
    """Start a chain. Any existing unchained content is anchored by its size and SHA-256."""
    data = b""
    if os.path.isfile(path):
        with open(path, "rb") as f:
            data = f.read()
        if data and not data.endswith(b"\n"):
            with open(path, "ab") as f:
                f.write(b"\n")
            data += b"\n"
    fields = "".join(f" | {k.upper()}={v}" for k, v in extra.items())
    return _write_line(path, key, ei.GENESIS_LINK, 0, _format(
        f"{GENESIS_MSG} | PRIOR_BYTES={len(data)} | PRIOR_SHA256={hashlib.sha256(data).hexdigest()} | "
        f"KEY_ID={ei.ledger_key_id(key)}{fields}"))


def append(path: str, line: str, key: bytes = None) -> None:
    """Append one formatted line, chained to whatever is currently last in the file."""
    key = key or ei.ledger_key()
    with _FileLock(path):
        prev = _last_chain(path)
        if prev is None:
            prev = _write_genesis(path, key)
        head = _read_head(path, key)
        if head and head[1] == prev:
            count = head[0]
        else:   # head missing or stale: count the chained lines once
            with open(path, "rb") as f:
                count = sum(1 for _, t in _split_lines(f.read()) if CHAIN_SEP in t)
        _write_line(path, key, prev, count, line)


class ChainedFileHandler(logging.Handler):
    """logging handler that appends HMAC-chained lines to the audit log."""

    def __init__(self, path: str, key: bytes = None):
        super().__init__(level=logging.INFO)
        setattr(self, HANDLER_TAG, True)
        self.path = path
        self.key  = key or ei.ledger_key()
        self.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def emit(self, record):
        try:
            append(self.path, self.format(record), self.key)
        except Exception:
            self.handleError(record)


def setup(path: str) -> ChainedFileHandler:
    """
    Attach exactly one chained handler for this log to the app's logger. Handlers
    left by an earlier version of this module (Streamlit reloads modules when
    their source changes) or an unchained FileHandler on the same file are removed.
    """
    target = os.path.abspath(path)
    app_logger = logging.getLogger(LOGGER_NAME)
    app_logger.setLevel(logging.INFO)
    for lg in (logging.getLogger(), app_logger):
        for h in list(lg.handlers):
            tagged = getattr(h, HANDLER_TAG, False) or type(h).__name__ == "ChainedFileHandler"
            same_file = os.path.abspath(getattr(h, "path", getattr(h, "baseFilename", ""))) == target
            keep = lg is app_logger and isinstance(h, ChainedFileHandler) and same_file   # this module version
            if (tagged or (isinstance(h, logging.FileHandler) and same_file)) and not keep:
                lg.removeHandler(h)
                h.close()
    existing = [h for h in app_logger.handlers if isinstance(h, ChainedFileHandler)
                and os.path.abspath(h.path) == target]
    if existing:
        for extra in existing[1:]:
            app_logger.removeHandler(extra)
        return existing[0]
    handler = ChainedFileHandler(path)
    app_logger.addHandler(handler)
    return handler


def archive_and_restart(path: str, reason: str, by: str, key: bytes = None) -> dict:
    """
    Move the current log (unchanged) and its head file to logs/archive/, write a
    verification report next to it, and start a new chain whose genesis line
    references the archived file's SHA-256, status and the reason.
    """
    key = key or ei.ledger_key()
    reason = re.sub(r"[|=\r\n]", "/", reason or "").strip()
    if len(reason) < 10:
        raise ValueError("A reason of at least 10 characters is required to archive the audit log.")
    with _FileLock(path):
        check = verify_log(path, key)
        with open(path, "rb") as f:
            data = f.read()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_dir = os.path.join(os.path.dirname(os.path.abspath(path)), "archive")
        os.makedirs(archive_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(path))[0]
        archived = os.path.join(archive_dir, f"{base}_{stamp}.log")
        os.replace(path, archived)
        if os.path.isfile(f"{path}.head"):
            os.replace(f"{path}.head", f"{archived}.head")
        sha = hashlib.sha256(data).hexdigest()
        status = "VERIFIED" if check["verified"] else "COMPROMISED"
        report = {
            "archived_log": os.path.basename(archived), "archived_local": ei.local_timestamp(),
            "archived_utc": ei._utc_now(), "archived_by": by, "reason": reason,
            "sha256": sha, "bytes": len(data), "status": status, "verification": check,
        }
        with open(f"{archived}.verification.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        _write_genesis(path, key, previous_log=os.path.basename(archived), previous_sha256=sha,
                       previous_status=status, archived_by=by, reason=reason)
    return report


def list_archives(path: str) -> list:
    """Verification reports of archived logs, oldest first, with the archive file's current hash re-checked."""
    archive_dir = os.path.join(os.path.dirname(os.path.abspath(path)), "archive")
    reports = []
    if os.path.isdir(archive_dir):
        for name in sorted(os.listdir(archive_dir)):
            if name.endswith(".verification.json"):
                with open(os.path.join(archive_dir, name), "r", encoding="utf-8") as f:
                    rep_ = json.load(f)
                log_path = os.path.join(archive_dir, rep_["archived_log"])
                rep_["path"] = log_path
                rep_["unchanged_since_archive"] = (
                    os.path.isfile(log_path) and ei.hash_file(log_path)["sha256"] == rep_["sha256"])
                reports.append(rep_)
    return reports


def verify_log(path: str, key: bytes = None) -> dict:
    """Re-verify the whole audit log chain, the genesis anchor and the head file."""
    key = key or ei.ledger_key()
    with open(path, "rb") as f:
        data = f.read()
    lines, problems = _split_lines(data), []
    genesis_idx = next((i for i, (_, t) in enumerate(lines) if GENESIS_MSG in t and CHAIN_SEP in t), None)
    if genesis_idx is None:
        return {"log": path, "verified": False, "chained_lines": 0, "legacy_lines": len(lines), "bad_lines": [],
                "problems": ["No chained entries - the log was never protected or the genesis line was removed"]}

    # Genesis anchors the unchained history that precedes it
    offset, genesis = lines[genesis_idx]
    fields = dict(p.split("=", 1) for p in genesis.split(" | ") if "=" in p)
    prior = data[:offset]
    if (fields.get("PRIOR_BYTES") != str(len(prior))
            or fields.get("PRIOR_SHA256") != hashlib.sha256(prior).hexdigest()):
        problems.append("Unchained history before the genesis line was modified")

    prev, count, bad_lines = ei.GENESIS_LINK, 0, []
    for n, (_, text) in enumerate(lines[genesis_idx:], start=genesis_idx + 1):
        if CHAIN_SEP not in text:
            problems.append(f"Line {n}: unchained line inserted into the protected log")
            bad_lines.append(n)
            continue
        body, mac = text.rsplit(CHAIN_SEP, 1)
        if not hmac.compare_digest(_mac(key, prev, body), mac.strip()):
            if n - 2 >= 0 and lines[n - 2][1] == text:
                problems.append(f"Line {n}: duplicate of line {n - 1} (same entry written twice - "
                                "a second log writer was active)")
            else:
                problems.append(f"Line {n}: chain broken (line edited, inserted, removed or reordered)")
            bad_lines.append(n)
        prev, count = mac.strip(), count + 1

    head_path = f"{path}.head"
    if not os.path.isfile(head_path):
        problems.append("Head file missing - truncation of the log tail cannot be ruled out")
    else:
        with open(head_path, "r", encoding="utf-8") as f:
            parts = f.read().split()
        if (len(parts) != 3 or not parts[0].isdigit()
                or not hmac.compare_digest(_head_mac(key, int(parts[0]), parts[1]), parts[2])):
            problems.append("Head file altered or forged")
        elif int(parts[0]) != count or parts[1] != prev:
            problems.append(f"Log has {count} chained lines but the head records {parts[0]} - "
                            "lines were removed from the end (truncation)")

    return {"log": path, "verified": not problems, "chained_lines": count,
            "legacy_lines": genesis_idx, "bad_lines": bad_lines, "problems": problems}


_FIELD_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")


def read_entries(path: str, bad_lines=()) -> list:
    """
    Parse the audit log into records: line number, timestamp, level, category
    (first message segment, e.g. AUTH / CUSTODY), KEY=value fields (first
    occurrence wins), the full message and the line's chain status.
    """
    if not os.path.isfile(path):
        return []
    with open(path, "rb") as f:
        lines = _split_lines(f.read())
    genesis = next((i for i, (_, t) in enumerate(lines) if GENESIS_MSG in t and CHAIN_SEP in t), len(lines))
    bad, entries = set(bad_lines), []
    for n, (_, text) in enumerate(lines, start=1):
        body = text.rsplit(CHAIN_SEP, 1)[0] if CHAIN_SEP in text else text
        parts = body.split(" | ")
        segments = parts[2:] if len(parts) > 2 else parts[1:]
        fields = {}
        for seg in segments[1:]:
            m = _FIELD_RE.match(seg.strip())
            if m and m.group(1) not in fields:
                fields[m.group(1)] = m.group(2).strip()
        entries.append({
            "line": n,
            "timestamp": parts[0].strip(),
            "level": parts[1].strip() if len(parts) > 2 else "",
            "category": segments[0].strip() if segments else "",
            "fields": fields,
            "message": " | ".join(segments),
            "chain": "broken" if n in bad else "legacy" if n <= genesis else "ok",
        })
    return entries


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "verify":
        log_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ei.BASE_DIR, "logs", "triage_audit.log")
        res = verify_log(log_path)
        print(f"{'VERIFIED   ' if res['verified'] else 'COMPROMISED'}  {log_path}  "
              f"({res['chained_lines']} chained lines, {res['legacy_lines']} anchored legacy lines)")
        for problem in res["problems"]:
            print(f"    - {problem}")
        sys.exit(0 if res["verified"] else 1)
    if len(sys.argv) >= 4 and sys.argv[1] == "archive" and sys.argv[2] == "--reason":
        log_path = sys.argv[4] if len(sys.argv) > 4 else os.path.join(ei.BASE_DIR, "logs", "triage_audit.log")
        rep_ = archive_and_restart(log_path, sys.argv[3], by=f"cli:{getpass.getuser()}")
        print(f"Archived {rep_['archived_log']} ({rep_['status']}, SHA-256 {rep_['sha256']})")
        print("A new chain was started; its genesis line references the archived log.")
        sys.exit(0)
    print("Usage: python -m memtriage.audit_log verify [log]\n"
          "       python -m memtriage.audit_log archive --reason \"<why>\" [log]")
    sys.exit(2)
