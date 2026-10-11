"""
Evidence Integrity & Chain of Custody
=====================================
Cryptographic hashing (SHA-256 + MD5) of every artefact handled by the triage
tool, and a tamper-evident chain-of-custody ledger that re-verifies those
hashes at every processing stage:

    acquisition → working copy → pre-extraction → post-extraction →
    derived CSV → pre-analysis → analysis input → pre-report → report

Each custody event stores the link hash of the previous event. Link hashes are
HMAC-SHA256 values keyed with a secret ledger key (keys/ledger_hmac.key or the
FORENSICS_LEDGER_KEY environment variable), so a ledger cannot be edited and
re-chained without that key. Model files are also verified against pinned
SHA-256 hashes (models/model_hashes.json) before they are unpickled.

Verify an exported manifest from the command line:
    python evidence_integrity.py verify outputs/cases/<case>/<evidence-id>/custody_manifest.json
"""

import os
import io
import sys
import json
import hmac
import stat
import hashlib
import secrets
import functools
from datetime import datetime, timezone

import pandas as pd


CHUNK_SIZE = 8 * 1024 * 1024   # 8 MB streaming reads (memory dumps can be many GB)

STATUS_RECORDED = "RECORDED"   # first time a hash is taken (baseline)
STATUS_MATCH    = "MATCH"      # re-computed hash equals the baseline
STATUS_MISMATCH = "MISMATCH"   # re-computed hash differs → integrity violated
STATUS_MISSING  = "MISSING"    # artefact could not be re-read for verification

GENESIS_LINK = "0" * 64

BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
LEDGER_KEY_ENV    = "FORENSICS_LEDGER_KEY"            # optional hex-encoded key (overrides the key file)
LEDGER_KEY_PATH   = os.path.join(BASE_DIR, "keys", "ledger_hmac.key")
LINK_ALGORITHM    = "HMAC-SHA256"
MODEL_HASHES_PATH = os.path.join(BASE_DIR, "models", "model_hashes.json")


# ── Hashing primitives ────────────────────────────────────────────────────────
def hash_file(path: str) -> dict:
    """Stream a file from disk and return its SHA-256, MD5 and size."""
    sha256, md5, size = hashlib.sha256(), hashlib.md5(), 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "size": size}


def hash_stream(stream) -> dict:
    """Hash a binary file-like object (e.g. a Streamlit upload) from its start."""
    sha256, md5, size = hashlib.sha256(), hashlib.md5(), 0
    stream.seek(0)
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        sha256.update(chunk)
        md5.update(chunk)
        size += len(chunk)
    stream.seek(0)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "size": size}


def hash_bytes(data: bytes) -> dict:
    return hash_stream(io.BytesIO(data))


def hash_feature_row(row_df: pd.DataFrame) -> str:
    """
    Canonical SHA-256 of the exact feature values submitted to the models.
    Values are serialised with full float precision in a fixed column order.
    """
    canonical = row_df.to_csv(index=False, float_format="%.10g", lineterminator="\n")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def make_read_only(path: str):
    """Write-protect an evidence working copy."""
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


def format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.2f} {unit}"
        n /= 1024


# ── Chain of custody ledger ───────────────────────────────────────────────────
class CustodyChain:
    """Ordered, hash-linked record of every integrity check for one evidence item in a case."""

    def __init__(self, case_id: str, evidence_name: str, evidence_kind: str, log=None,
                 evidence_id: str = "", analyst: str = ""):
        self.log           = log   # optional logging.Logger mirroring every event
        self.case_id       = case_id       # analyst-assigned case number
        self.evidence_id   = evidence_id   # unique ID of this evidence item within the case
        self.analyst       = analyst       # examiner responsible for every recorded action
        self.evidence_name = evidence_name
        self.evidence_kind = evidence_kind
        self.created_utc   = _utc_now()
        self.events        = []
        # Baseline hashes per artefact role, e.g. {"evidence": {...}, "csv": {...}}
        self.baselines     = {}
        # Where the evidence came from and who it is prepared for (recorded at acquisition)
        self.provenance    = {}

    # ── recording ──
    def record(self, stage: str, action: str, artifact: str, hashes: dict = None,
               role: str = None, details: str = "", status: str = None) -> dict:
        """
        Add a custody event. If `role` already has a baseline, the new hash is
        compared to it (MATCH / MISMATCH); otherwise it becomes the baseline.
        """
        hashes = hashes or {}
        expected = self.baselines.get(role, {}).get("sha256") if role else None
        if status is None:
            if not hashes:
                status = STATUS_MISSING
            elif expected is None:
                status = STATUS_RECORDED
                if role:
                    self.baselines[role] = dict(hashes, artifact=artifact)
            else:
                status = STATUS_MATCH if hashes.get("sha256") == expected else STATUS_MISMATCH

        prev_link = self.events[-1]["link_hash"] if self.events else GENESIS_LINK
        event = {
            "seq":       len(self.events) + 1,
            "timestamp": _utc_now(),
            "stage":     stage,
            "analyst":   self.analyst,
            "action":    action,
            "artifact":  artifact,
            "role":      role or "",
            "sha256":    hashes.get("sha256", ""),
            "md5":       hashes.get("md5", ""),
            "size":      hashes.get("size", ""),
            "expected_sha256": expected or "",
            "status":    status,
            "details":   details,
            "prev_link": prev_link,
        }
        event["link_hash"] = _link_hash(event)
        self.events.append(event)
        if self.log:
            log_fn = self.log.error if status == STATUS_MISMATCH else self.log.info
            log_fn(
                f"CUSTODY | CASE={self.case_id} | EVIDENCE={self.evidence_id} | ANALYST={self.analyst} | "
                f"SEQ={event['seq']} | STAGE={stage} | "
                f"ARTIFACT={artifact} | SHA256={event['sha256'] or '-'} | MD5={event['md5'] or '-'} | "
                f"STATUS={status} | LINK={event['link_hash'][:16]}"
            )
        return event

    def verify_file(self, stage: str, action: str, path: str, role: str, details: str = "") -> dict:
        """Re-hash a file on disk and compare it with the role's baseline."""
        artifact = os.path.basename(path)
        if not path or not os.path.isfile(path):
            return self.record(stage, action, artifact or "(unavailable)", role=role,
                               details=details or "Artefact not accessible for re-verification",
                               status=STATUS_MISSING)
        return self.record(stage, action, artifact, hash_file(path), role=role, details=details)

    # ── verification ──
    def ledger_intact(self) -> bool:
        """Recompute every link hash; False if any custody event was altered."""
        prev = GENESIS_LINK
        for ev in self.events:
            if ev["prev_link"] != prev or not hmac.compare_digest(_link_hash(ev), ev["link_hash"]):
                return False
            prev = ev["link_hash"]
        return True

    @property
    def mismatches(self) -> list:
        return [e for e in self.events if e["status"] == STATUS_MISMATCH]

    @property
    def is_intact(self) -> bool:
        return not self.mismatches and self.ledger_intact()

    @property
    def head_hash(self) -> str:
        return self.events[-1]["link_hash"] if self.events else GENESIS_LINK

    def baseline(self, role: str) -> dict:
        return self.baselines.get(role, {})

    # ── export ──
    def to_dict(self) -> dict:
        return {
            "case_number":    self.case_id,
            "evidence_id":    self.evidence_id,
            "analyst":        self.analyst,
            "evidence_name":  self.evidence_name,
            "evidence_kind":  self.evidence_kind,
            "created_utc":    self.created_utc,
            "integrity":      "VERIFIED" if self.is_intact else "COMPROMISED",
            "ledger_intact":  self.ledger_intact(),
            "link_algorithm": LINK_ALGORITHM,
            "ledger_key_id":  ledger_key_id(),
            "head_link_hash": self.head_hash,
            "provenance":     self.provenance,
            "baselines":      self.baselines,
            "events":         self.events,
        }

    def save_manifest(self, path: str) -> str:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        return path

    def events_dataframe(self) -> pd.DataFrame:
        rows = [{
            "#":        e["seq"],
            "Time (UTC)": e["timestamp"],
            "Stage":    e["stage"],
            "Analyst":  e.get("analyst", ""),
            "Action":   e["action"],
            "Artefact": e["artifact"],
            "SHA-256":  e["sha256"],
            "Status":   e["status"],
        } for e in self.events]
        return pd.DataFrame(rows)


def new_evidence_id(evidence_sha256: str) -> str:
    """Unique evidence item ID: acquisition time + first 8 hex of the SHA-256."""
    return f"EV-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{evidence_sha256[:8].upper()}"


def suggest_case_number() -> str:
    return f"MF-{datetime.now().strftime('%Y%m%d-%H%M')}"


def local_timestamp(dt: datetime = None) -> str:
    """Local wall-clock time with explicit UTC offset, e.g. 2026-10-01 22:50:18 UTC+05:30."""
    dt = (dt or datetime.now()).astimezone()
    off = dt.strftime("%z")
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC{off[:3]}:{off[3:]}"


def write_hash_sidecar(path: str, hashes: dict) -> str:
    """Write a `<file>.sha256` sidecar in the standard `sha256sum` format."""
    sidecar = f"{path}.sha256"
    with open(sidecar, "w", encoding="utf-8") as f:
        f.write(f"{hashes['sha256']}  {os.path.basename(path)}\n")
    return sidecar


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _link_hash(event: dict, key: bytes = None) -> str:
    fields = ["seq", "timestamp", "stage", "analyst", "action", "artifact", "role", "sha256", "md5",
              "size", "expected_sha256", "status", "details", "prev_link"]
    payload = "|".join(str(event.get(k, "")) for k in fields)
    return hmac.new(key or ledger_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


# ── Ledger key ────────────────────────────────────────────────────────────────
@functools.lru_cache(maxsize=1)
def ledger_key() -> bytes:
    """
    Secret key for the custody ledger HMAC. Taken from FORENSICS_LEDGER_KEY (hex)
    if set, otherwise from keys/ledger_hmac.key, which is created with 256 random
    bits on first use and write-protected. The key must never leave the lab.
    """
    env = os.environ.get(LEDGER_KEY_ENV, "").strip()
    if env:
        key = bytes.fromhex(env)
        if len(key) < 32:
            raise ValueError(f"{LEDGER_KEY_ENV} must be at least 32 bytes (64 hex characters)")
        return key
    if not os.path.isfile(LEDGER_KEY_PATH):
        os.makedirs(os.path.dirname(LEDGER_KEY_PATH), exist_ok=True)
        try:
            fd = os.open(LEDGER_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o400)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        except FileExistsError:
            pass   # created concurrently by another session
        make_read_only(LEDGER_KEY_PATH)
    with open(LEDGER_KEY_PATH, "rb") as f:
        key = f.read()
    if len(key) < 32:
        raise ValueError(f"Ledger key file is invalid (expected 32 bytes): {LEDGER_KEY_PATH}")
    return key


def ledger_key_id(key: bytes = None) -> str:
    """Public fingerprint of the ledger key (identifies which key sealed a manifest; reveals nothing about it)."""
    return hashlib.sha256(b"ledger-key-id|" + (key or ledger_key())).hexdigest()[:16].upper()


def verify_manifest(path: str, key: bytes = None) -> dict:
    """
    Independently re-verify an exported custody manifest: recompute every HMAC
    link from the events themselves (the stored "integrity" field is not trusted).
    """
    key = key or ledger_key()
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    events = manifest.get("events", [])
    problems, prev = [], GENESIS_LINK
    if manifest.get("link_algorithm") != LINK_ALGORITHM:
        problems.append(f"Unsupported link algorithm: {manifest.get('link_algorithm') or 'unkeyed SHA-256 (legacy)'}")
    if manifest.get("ledger_key_id") and manifest["ledger_key_id"] != ledger_key_id(key):
        problems.append("Manifest was sealed with a different ledger key")
    for ev in events:
        if ev.get("prev_link") != prev:
            problems.append(f"Event {ev.get('seq')}: broken link to previous event")
        if not hmac.compare_digest(_link_hash(ev, key), str(ev.get("link_hash", ""))):
            problems.append(f"Event {ev.get('seq')}: link HMAC does not match (event altered or forged)")
        if ev.get("status") == STATUS_MISMATCH:
            problems.append(f"Event {ev.get('seq')}: recorded hash MISMATCH at stage {ev.get('stage')}")
        prev = ev.get("link_hash", "")
    if manifest.get("head_link_hash", GENESIS_LINK) != prev:
        problems.append("Head link hash does not match the last event (events removed or appended)")
    return {"manifest": path, "events": len(events), "verified": not problems, "problems": problems}


# ── Model integrity ───────────────────────────────────────────────────────────
class ModelIntegrityError(Exception):
    """Raised when a model file is not pinned or its hash differs from the pinned hash."""


def pin_model_hashes(model_dir: str = None, out_path: str = MODEL_HASHES_PATH) -> dict:
    """Record the SHA-256 of every .pkl model (run after (re)training a model)."""
    model_dir = model_dir or os.path.dirname(out_path)
    pins = {name: hash_file(os.path.join(model_dir, name))["sha256"]
            for name in sorted(os.listdir(model_dir)) if name.endswith(".pkl")}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"algorithm": "SHA-256", "pinned_utc": _utc_now(), "models": pins}, f, indent=2)
        f.write("\n")
    return pins


def load_verified_model(path: str, pins_path: str = MODEL_HASHES_PATH):
    """
    Read a pickled model once, check its SHA-256 against the pinned value, and
    unpickle those same verified bytes (no window to swap the file in between).
    Returns (model, sha256).
    """
    import joblib
    name = os.path.basename(path)
    if not os.path.isfile(pins_path):
        raise ModelIntegrityError(f"Model hash pin file missing: {pins_path}. "
                                  "Run: python scripts/pin_model_hashes.py")
    with open(pins_path, "r", encoding="utf-8") as f:
        pinned = json.load(f).get("models", {}).get(name)
    if not pinned:
        raise ModelIntegrityError(f"{name} has no pinned hash in {os.path.basename(pins_path)}")
    with open(path, "rb") as f:
        data = f.read()
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, pinned.lower()):
        raise ModelIntegrityError(f"{name} SHA-256 {actual} does not match pinned {pinned} "
                                  "- the model file was modified or replaced")
    return joblib.load(io.BytesIO(data)), actual


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "verify":
        all_ok = True
        for manifest_path in sys.argv[2:]:
            res = verify_manifest(manifest_path)
            all_ok &= res["verified"]
            print(f"{'VERIFIED   ' if res['verified'] else 'COMPROMISED'}  {manifest_path}  ({res['events']} events)")
            for problem in res["problems"]:
                print(f"    - {problem}")
        sys.exit(0 if all_ok else 1)
    print("Usage: python evidence_integrity.py verify <custody_manifest.json> [...]")
    sys.exit(2)
