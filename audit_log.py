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

Verify from the command line:
    python audit_log.py verify [logs/triage_audit.log]
"""

import os
import re
import sys
import hmac
import hashlib
import logging

import evidence_integrity as ei


CHAIN_SEP   = " | CHAIN="
GENESIS_MSG = "AUDIT LOG CHAIN GENESIS"
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


class ChainedFileHandler(logging.Handler):
    """logging handler that appends HMAC-chained lines to the audit log."""

    def __init__(self, path: str, key: bytes = None):
        super().__init__(level=logging.INFO)
        self.path      = path
        self.head_path = f"{path}.head"
        self.key       = key or ei.ledger_key()
        self.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.prev, self.count = self._resume()

    def _resume(self):
        data = b""
        if os.path.isfile(self.path):
            with open(self.path, "rb") as f:
                data = f.read()
        chained = [text for _, text in _split_lines(data) if CHAIN_SEP in text]
        if chained:
            return chained[-1].rsplit(CHAIN_SEP, 1)[1].strip(), len(chained)

        # First run with chaining: anchor the existing (unchained) history.
        if data and not data.endswith(b"\n"):
            with open(self.path, "ab") as f:
                f.write(b"\n")
            data += b"\n"
        self.prev, self.count = ei.GENESIS_LINK, 0
        self._append(logging.Formatter(LOG_FORMAT, DATE_FORMAT).format(logging.LogRecord(
            "audit", logging.INFO, __file__, 0,
            f"{GENESIS_MSG} | PRIOR_BYTES={len(data)} | PRIOR_SHA256={hashlib.sha256(data).hexdigest()} | "
            f"KEY_ID={ei.ledger_key_id(self.key)}", None, None)))
        return self.prev, self.count

    def _append(self, line: str):
        line = _escape(line)
        mac  = _mac(self.key, self.prev, line)
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"{line}{CHAIN_SEP}{mac}\n")
        self.prev, self.count = mac, self.count + 1
        tmp = f"{self.head_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(f"{self.count} {mac} {_head_mac(self.key, self.count, mac)}\n")
        os.replace(tmp, self.head_path)

    def emit(self, record):
        try:
            self._append(self.format(record))   # Handler.handle() already holds self.lock
        except Exception:
            self.handleError(record)


def setup(path: str) -> ChainedFileHandler:
    """Attach the chained handler to the root logger once per process (Streamlit reruns app.py)."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    target = os.path.abspath(path)
    for h in list(root.handlers):
        if isinstance(h, ChainedFileHandler) and os.path.abspath(h.path) == target:
            return h
        if isinstance(h, logging.FileHandler) and os.path.abspath(h.baseFilename) == target:
            root.removeHandler(h)   # unchained writer to the same file would break the chain
            h.close()
    handler = ChainedFileHandler(path)
    root.addHandler(handler)
    return handler


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
    print("Usage: python audit_log.py verify [logs/triage_audit.log]")
    sys.exit(2)
