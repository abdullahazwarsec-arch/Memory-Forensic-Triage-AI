"""
Input Validation
================
Security gates applied to evidence before it reaches the case folder or the ML
models:

* Upload gates - size limits, text/CSV structure checks for feature CSVs and
  file-signature checks for memory images, run before a case record is created.
* Feature gate - verifies that the 55 features the model was trained on are
  present, numeric, finite and non-negative. Missing or empty features would
  otherwise be silently zero-filled, which can push a verdict towards "benign".
"""

import os
import io
import json
import shutil
import hashlib

import numpy as np
import pandas as pd


# ── Limits ────────────────────────────────────────────────────────────────────
MAX_CSV_BYTES        = 50 * 1024 * 1024        # a 55-feature CSV is a few KB per row
MIN_DUMP_BYTES       = 64 * 1024 * 1024        # no Windows system runs in less RAM
DISK_HEADROOM_BYTES  = 1024 * 1024 * 1024      # free space kept after copying a dump
MAX_MISSING_FRACTION = 0.20                    # above this, a verdict is meaningless → blocked

SEVERITY_OK, SEVERITY_WARN, SEVERITY_BLOCK = "ok", "warn", "block"


class UploadRejected(Exception):
    """Raised when an uploaded or referenced file fails an intake check."""


# ── Feature CSV intake ────────────────────────────────────────────────────────
def check_csv_upload(stream, size: int, expected_cols: list) -> None:
    """Reject oversized, binary, unparsable or unrelated files before a case is opened."""
    if size == 0:
        raise UploadRejected("The file is empty.")
    if size > MAX_CSV_BYTES:
        raise UploadRejected(f"CSV is {size / 1024 / 1024:,.1f} MB; the limit for a feature CSV is "
                             f"{MAX_CSV_BYTES // 1024 // 1024} MB.")
    stream.seek(0)
    head = stream.read(64 * 1024)
    stream.seek(0)
    if b"\x00" in head:
        raise UploadRejected("The file contains binary data (NUL bytes) - it is not a CSV text file.")
    try:
        head.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        # A multi-byte character cut at the 64 KB boundary is fine; anything earlier is not text.
        if e.start < len(head) - 4:
            raise UploadRejected("The file is not UTF-8 text - it is not a CSV file.")
    try:
        header = pd.read_csv(io.BytesIO(head), nrows=0).columns
    except Exception as e:
        raise UploadRejected(f"The file could not be parsed as CSV: {e}")
    if not set(header) & set(expected_cols):
        raise UploadRejected("None of the 55 Volatility memory features appear in the CSV header - "
                             "this is not a memory-feature CSV.")


# ── Memory image intake ───────────────────────────────────────────────────────
# (offset, magic, description) of formats Volatility 3 can read. Raw images
# (.raw/.mem/.vmem/.bin/.img) have no header: they start with physical page 0.
MEMORY_SIGNATURES = [
    (0, b"PAGEDU64", "Windows 64-bit crash dump"),
    (0, b"PAGEDUMP", "Windows 32-bit crash dump"),
    (0, b"EMiL",     "LiME memory image"),
    (0, b"\x7fELF",  "ELF core memory image"),
    (0, b"hibr",     "Windows hibernation file"),
    (0, b"HIBR",     "Windows hibernation file"),
    (0, b"wake",     "Windows hibernation file"),
    (0, b"WAKE",     "Windows hibernation file"),
]

# Signatures of common file types that are certainly not memory images
NON_MEMORY_SIGNATURES = [
    (b"PK\x03\x04", "ZIP / Office document"),
    (b"Rar!",       "RAR archive"),
    (b"7z\xbc\xaf", "7-Zip archive"),
    (b"\x1f\x8b",   "GZIP archive"),
    (b"%PDF",       "PDF document"),
    (b"MZ",         "Windows executable"),
    (b"\x89PNG",    "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"EVF\x09",    "EnCase E01 container (convert to raw first)"),
    (b"KDMV",       "VMware virtual disk"),
    (b"conectix",   "Virtual hard disk"),
]

EXTENSION_SIGNATURES = {
    "dmp":  (b"PAGEDU64", b"PAGEDUMP"),
    "lime": (b"EMiL",),
}


def check_memory_image(path_or_stream, size: int, name: str, dump_extensions: list) -> str:
    """
    Validate a memory image by extension, size and file signature.
    Returns a short description of the detected format.
    """
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    if ext not in dump_extensions:
        raise UploadRejected(f"'.{ext or '?'}' is not a supported memory image type "
                             f"({', '.join('.' + e for e in dump_extensions)}).")
    if size < MIN_DUMP_BYTES:
        raise UploadRejected(f"The file is only {size / 1024 / 1024:,.1f} MB - too small to be a Windows "
                             f"memory image (minimum {MIN_DUMP_BYTES // 1024 // 1024} MB).")

    if isinstance(path_or_stream, str):
        with open(path_or_stream, "rb") as f:
            head = f.read(4096)
    else:
        path_or_stream.seek(0)
        head = path_or_stream.read(4096)
        path_or_stream.seek(0)

    for magic, desc in NON_MEMORY_SIGNATURES:
        if head.startswith(magic):
            raise UploadRejected(f"The file signature identifies a {desc}, not a memory image.")
    if ext in EXTENSION_SIGNATURES and not head.startswith(EXTENSION_SIGNATURES[ext]):
        raise UploadRejected(f"A .{ext} file must start with the "
                             f"{' or '.join(m.decode() for m in EXTENSION_SIGNATURES[ext])} signature; "
                             "this file does not.")
    for offset, magic, desc in MEMORY_SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            return desc
    return "Raw physical memory image (headerless)"


def check_disk_space(target_dir: str, needed: int) -> None:
    """Refuse to copy evidence that would exhaust the evidence volume."""
    os.makedirs(target_dir, exist_ok=True)
    free = shutil.disk_usage(target_dir).free
    if free < needed + DISK_HEADROOM_BYTES:
        raise UploadRejected(f"Not enough free disk space for a working copy: {free / 1024**3:,.1f} GB free, "
                             f"{(needed + DISK_HEADROOM_BYTES) / 1024**3:,.1f} GB needed. "
                             "Analyse the image in place using the local path option instead.")


# ── Feature gate ──────────────────────────────────────────────────────────────
def check_features(df: pd.DataFrame, expected_cols: list) -> dict:
    """
    Validate a feature table against the model's expected features.
    severity: "ok"    - every feature present, numeric, finite and non-negative
              "warn"  - some features missing / non-numeric / empty → analyst must acknowledge
              "block" - too many features missing, or infinite / negative values present
    """
    missing  = [c for c in expected_cols if c not in df.columns]
    present  = [c for c in expected_cols if c in df.columns]
    raw      = df[present]
    numeric  = raw.apply(pd.to_numeric, errors="coerce")
    empty    = raw.isna()
    invalid  = numeric.isna() & ~empty                                # text where a number belongs
    no_data  = [c for c in present if numeric[c].isna().all()]       # column holds no usable number

    empty_cells   = int(empty.sum().sum())
    invalid_cells = int(invalid.sum().sum())
    values   = numeric.to_numpy(dtype=float)
    inf_rows = sorted(set(np.where(np.isinf(values))[0].tolist()))
    neg_rows = sorted(set(np.where(values < 0)[0].tolist()))
    unusable = missing + no_data

    problems, severity = [], SEVERITY_OK
    if missing:
        problems.append(f"{len(missing)} of {len(expected_cols)} model features are missing and would be treated as 0")
        severity = SEVERITY_WARN
    if no_data:
        problems.append(f"{len(no_data)} feature column(s) contain no numeric data")
        severity = SEVERITY_WARN
    if invalid_cells:
        problems.append(f"{invalid_cells} non-numeric value(s) would be treated as 0")
        severity = SEVERITY_WARN
    if empty_cells:
        problems.append(f"{empty_cells} empty value(s) would be treated as 0")
        severity = SEVERITY_WARN
    if len(unusable) > MAX_MISSING_FRACTION * len(expected_cols):
        problems.append(f"more than {MAX_MISSING_FRACTION:.0%} of the features are unusable - "
                        "no meaningful verdict is possible")
        severity = SEVERITY_BLOCK
    if inf_rows:
        problems.append(f"infinite values in row(s) {_rows(inf_rows)}")
        severity = SEVERITY_BLOCK
    if neg_rows:
        problems.append(f"negative values in row(s) {_rows(neg_rows)} - memory feature counts cannot be negative")
        severity = SEVERITY_BLOCK

    report = {
        "severity":     severity,
        "expected":     len(expected_cols),
        "missing":      missing,
        "no_data":      no_data,
        "invalid_cells": invalid_cells,
        "empty_cells":  empty_cells,
        "inf_rows":     inf_rows,
        "negative_rows": neg_rows,
        "problems":     problems,
    }
    report["sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode("utf-8")).hexdigest()
    return report


def feature_matrix(df: pd.DataFrame, expected_cols: list) -> pd.DataFrame:
    """
    The exact matrix submitted to the models: expected columns in training order,
    non-numeric values and empty cells → 0, missing columns → 0. Only call after
    check_features() has passed or been acknowledged.
    """
    present = [c for c in expected_cols if c in df.columns]
    numeric = df[present].apply(pd.to_numeric, errors="coerce")
    return numeric.reindex(columns=expected_cols).fillna(0).astype(float)


def summary(report: dict) -> str:
    if report["severity"] == SEVERITY_OK:
        return f"PASSED - all {report['expected']} model features present, numeric, finite and non-negative"
    return ("BLOCKED - " if report["severity"] == SEVERITY_BLOCK else "ACCEPTED WITH WARNINGS - ") + \
        "; ".join(report["problems"])


def _rows(rows: list, limit: int = 10) -> str:
    shown = ", ".join(str(r) for r in rows[:limit])
    return shown + (f" (+{len(rows) - limit} more)" if len(rows) > limit else "")
