"""
Hash Checker page
=================
Stand-alone integrity checks, independent of any case:

1. Verify a file - a memory image, raw memory dump or CSV (uploaded, or by
   path for large dumps) is hashed with SHA-256, SHA-1 and MD5 and compared
   with the expected hash (pasted, or read from a .sha256 / .md5 / tool log).
2. Verify a dump -> CSV conversion - using the extraction report HazMem wrote
   when it converted the dump: the image hash before and after conversion must
   be identical, the CSV must hash to the value recorded when it was created
   and, optionally, the memory image must still match. With the case's
   HMAC-sealed custody manifest the same chain is proven tamper-evidently.

Every check is written to the audit log.
"""

import io
import json
import logging
import os
import re

import pandas as pd
import streamlit as st

from . import evidence_integrity as ei
from . import timing
from . import ui_theme as ui

OUTPUT_DIR = None            # set by app.py (timing statistics live there)
_log = logging.getLogger("triage.hashcheck")
ALGO_LABEL = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}


def _timings() -> timing.Timings:
    return timing.Timings(os.path.join(OUTPUT_DIR or ".", "timing_stats.json"))


def _user() -> str:
    return (st.session_state.get("auth_user") or {}).get("username", "-")


def _clean(text: str) -> str:
    return re.sub(r"[|=\r\n]", "/", str(text))[:120]


def _hash_with_eta(source, size: int, name: str) -> dict:
    """Hash an upload (file-like) or a path with a live progress bar and countdown."""
    tm = _timings()
    eta = timing.ProgressETA(tm.hash_seconds(size), f"Hashing {name}...")
    progress = lambda done, total: eta.update(done / max(total, 1), f"Hashing {name}... {done * 100 // max(total, 1)}%")
    hashes = ei.hash_file(source, progress) if isinstance(source, str) else ei.hash_stream(source, progress)
    seconds = eta.elapsed
    eta.empty()
    tm.record_hash(size, seconds)
    return dict(hashes, seconds=seconds)


def compare(computed: dict, candidates: list) -> list:
    """[(algorithm, expected, computed, matched, filename_in_hash_file)] for every expected digest."""
    rows = []
    for digest, fname in candidates:
        algo = ei.detect_algorithm(digest)
        if algo:
            rows.append((algo, digest, computed[algo], digest == computed[algo], fname))
    return rows


def _hash_rows(computed: dict, rows: list) -> str:
    by_algo = {r[0]: r for r in rows}
    html = []
    for algo in ("sha256", "sha1", "md5"):
        r = by_algo.get(algo)
        status = ("" if r is None else ui.pill("Match", "good") if r[3] else ui.pill("MISMATCH", "critical"))
        expected = "" if r is None else (f'<div class="fx-hash-label" style="margin-top:.35rem;">Expected</div>'
                                         f'<div class="fx-hash-value">{ui.esc(r[1])}</div>')
        html.append(f'<div class="fx-hash" style="display:flex;gap:1rem;justify-content:space-between;align-items:flex-start;">'
                    f'<div style="min-width:0;"><div class="fx-hash-label">{ALGO_LABEL[algo]} — computed</div>'
                    f'<div class="fx-hash-value">{ui.esc(computed[algo])}</div>{expected}</div>'
                    f'<div style="flex:0 0 auto;">{status}</div></div>')
    return "".join(html)


# ── 1. Verify a file ──────────────────────────────────────────────────────────
def _render_file_check():
    st.markdown("Check that a **memory image**, **raw memory dump** or **CSV** is exactly the file you expect — "
                "for example the image the acquisition tool hashed, or a CSV whose `.sha256` file you were given.")
    source = st.segmented_control("File to check", ["upload", "path"], default="upload", key="hc_source",
                                  format_func={"upload": ":material/upload_file: Upload a file",
                                               "path": ":material/folder_open: Path on this computer"}.get) or "upload"
    uploaded, path, name, size = None, None, None, 0
    if source == "upload":
        uploaded = st.file_uploader("Memory image, raw dump or CSV", key="hc_file",
                                    help="Any file type. For dumps larger than a few GB use the path option.")
        if uploaded is not None:
            name, size = uploaded.name, uploaded.size
    else:
        path = st.text_input("Full path", placeholder=r"C:\Evidence\host01_memory.raw", key="hc_path").strip().strip('"')
        if path:
            if os.path.isfile(path):
                name, size = os.path.basename(path), os.path.getsize(path)
            else:
                st.error(f"File not found: `{path}`")
                path = None

    c1, c2 = st.columns([1.4, 1])
    with c1:
        pasted = st.text_area("Expected hash", height=110, key="hc_expected",
                              placeholder="Paste a SHA-256, SHA-1 or MD5 — or the text of a .sha256 / .md5 file, "
                                          "certutil output or the acquisition tool's log.")
    with c2:
        sidecar = st.file_uploader("…or the hash file itself", key="hc_sidecar",
                                   type=["sha256", "sha1", "md5", "txt", "log"],
                                   help="sha256sum / md5sum format, certutil output, or a DumpIt / FTK Imager log.")
    if name:
        st.caption(f":material/timer: {ui.esc(name)} · {ei.format_size(size)} · estimated time "
                   f"{timing.approx(_timings().hash_seconds(size))}")

    if st.button("Compute & verify", type="primary", icon=":material/fingerprint:", disabled=not name, key="hc_go"):
        computed = _hash_with_eta(path or uploaded, size, name)
        text = pasted + ("\n" + sidecar.getvalue().decode("utf-8", errors="replace") if sidecar is not None else "")
        candidates = ei.parse_hash_text(text)
        rows = compare(computed, candidates)
        verdict = ("none" if not rows else "match" if all(r[3] for r in rows) else "mismatch")
        st.session_state["hc_result"] = {"name": name, "size": size, "computed": computed, "rows": rows,
                                         "verdict": verdict, "ignored": len(candidates) - len(rows)}
        _log.log(logging.WARNING if verdict == "mismatch" else logging.INFO,
                 f"HASH CHECK | USER={_user()} | FILE={_clean(name)} | SIZE={size} | SHA256={computed['sha256']} | "
                 f"RESULT={verdict.upper()}" + (f" | ALGORITHMS={','.join(ALGO_LABEL[r[0]] for r in rows)}" if rows else ""))

    res = st.session_state.get("hc_result")
    if not res:
        return
    if res["verdict"] == "match":
        algos = ", ".join(ALGO_LABEL[r[0]] for r in res["rows"])
        banner = ui.banner("verified", "MATCH — the file is exactly the expected one",
                           f"{ui.esc(res['name'])} matches the expected {algos}.", "good")
    elif res["verdict"] == "mismatch":
        banner = ui.banner("gpp_bad", "MISMATCH — this is NOT the expected file",
                           f"{ui.esc(res['name'])} differs from the expected hash. It may be a different, incomplete "
                           "or altered file — do not use it as evidence until this is explained.", "critical")
    else:
        banner = ui.banner("fingerprint", "Fingerprint computed",
                           "No expected hash was given, so nothing was compared. Keep these values (or download the "
                           ".sha256 file) to verify this file later.", "accent")
    ui.render_html(banner)
    for r in res["rows"]:
        if r[4] and r[4] != res["name"]:
            st.warning(f"The hash file refers to **{r[4]}**, but the checked file is **{res['name']}**.",
                       icon=":material/warning:")
    if res["ignored"]:
        st.caption(f"{res['ignored']} value(s) in the expected text were not recognised as SHA-256, SHA-1 or MD5.")
    ui.render_html(f'<div class="fx-card" style="margin-top:.8rem;">{_hash_rows(res["computed"], res["rows"])}'
                   f'<div class="fx-kpi-sub" style="margin-top:.8rem;">{ei.format_size(res["size"])} hashed in '
                   f'{res["computed"]["seconds"]:.1f} s</div></div>')
    st.download_button("Download fingerprint (.sha256)", f"{res['computed']['sha256']}  {res['name']}\n",
                        file_name=f"{res['name']}.sha256", mime="text/plain", icon=":material/download:",
                        key="hc_dl")


# ── 2. Verify a dump → CSV conversion ────────────────────────────────────────
def _step(ok, title: str, detail: str) -> str:
    tone, glyph = ({True: ("good", "check_circle"), False: ("critical", "cancel"), None: ("neutral", "remove")})[ok]
    return ui.banner(glyph, title, detail, tone)


def conversion_checks(report: dict, csv_sha256: str, csv_name: str = "", dump_sha256: str = None,
                      manifest: dict = None) -> list:
    """
    The dump -> CSV chain as a list of (passed: True/False/None, title, detail-html):
    image unchanged by conversion, CSV equals the recorded one, (optional) image still
    matches, (optional) HMAC-sealed custody manifest records this image and CSV.
    """
    integ = report["integrity"]
    pre, post, recorded_csv = integ["pre_extraction"], integ["post_extraction"], integ["derived_csv"]
    code = lambda v: f"<code>{ui.esc(v or '—')}</code>"
    checks = [
        (pre.get("sha256") == post.get("sha256") and bool(pre.get("sha256")),
         "1 · Memory image unchanged by the conversion",
         f"Before: {code(pre.get('sha256'))}<br>After: {code(post.get('sha256'))}"),
        (csv_sha256 == recorded_csv.get("sha256"), "2 · CSV is the one produced by the conversion",
         f"Recorded: {code(recorded_csv.get('sha256'))}<br>This CSV: {code(csv_sha256)}"
         + ("" if not csv_name or csv_name == recorded_csv.get("file")
            else f"<br>Note: the report names the CSV <b>{ui.esc(recorded_csv.get('file', '?'))}</b>.")),
    ]
    if dump_sha256 is None:
        checks.append((None, "3 · Memory image not re-checked", "Add its path to re-hash the original image."))
    elif not dump_sha256:
        checks.append((False, "3 · Memory image is the one that was converted", "The image file was not found."))
    else:
        checks.append((dump_sha256 == pre.get("sha256"), "3 · Memory image is the one that was converted",
                       f"Recorded: {code(pre.get('sha256'))}<br>This image: {code(dump_sha256)}"))
    if manifest is not None:
        if not manifest:
            checks.append((False, "4 · Custody manifest confirms the chain", "Not a valid custody manifest."))
        else:
            sealed = ei.verify_manifest_data(manifest)
            base = manifest.get("baselines", {})
            linked = (base.get("evidence", {}).get("sha256") == pre.get("sha256")
                      and base.get("csv", {}).get("sha256") == csv_sha256)
            detail = ("HMAC-sealed ledger verified; it records this memory image and this exact CSV."
                      if sealed["verified"] and linked else "; ".join(sealed["problems"][:3]) if not sealed["verified"]
                      else "The sealed ledger records different hashes for the image or the CSV.")
            checks.append((sealed["verified"] and linked, "4 · Custody manifest confirms the chain", ui.esc(detail)))
    return checks


def _render_conversion_check():
    st.markdown("Prove that a feature **CSV** is exactly the one HazMem produced from a **memory image**, and that the "
                "image was not changed by the conversion. Use the files saved with every extraction "
                "(download them on the Analyse page after *Extract features*).")
    c1, c2 = st.columns(2)
    with c1:
        report_file = st.file_uploader("Extraction report (extraction_report.json)", type=["json"], key="cv_report")
        csv_file = st.file_uploader("Feature CSV", type=["csv"], key="cv_csv")
    with c2:
        dump_path = st.text_input("Memory image path (optional — re-hash the original)", key="cv_dump",
                                  placeholder=r"C:\Evidence\host01_memory.raw").strip().strip('"')
        manifest_file = st.file_uploader("Custody manifest (optional — tamper-evident proof)", type=["json"],
                                         key="cv_manifest",
                                         help="custody_manifest.json from the case folder: HMAC-sealed, so the "
                                              "recorded hashes themselves cannot have been edited.")
    ready = report_file is not None and csv_file is not None
    if not st.button("Verify conversion", type="primary", icon=":material/rule:", disabled=not ready, key="cv_go"):
        if not ready:
            st.caption("Add at least the extraction report and the CSV.")
        return

    try:
        report = json.loads(report_file.getvalue())
        pre = report["integrity"]["pre_extraction"]
    except (ValueError, KeyError, TypeError):
        st.error("This is not a HazMem extraction report (no integrity section).", icon=":material/error:")
        return
    csv_hashes = _hash_with_eta(io.BytesIO(csv_file.getvalue()), csv_file.size, csv_file.name)
    dump_sha256 = None
    if dump_path:
        dump_sha256 = (_hash_with_eta(dump_path, os.path.getsize(dump_path), os.path.basename(dump_path))["sha256"]
                       if os.path.isfile(dump_path) else "")
    manifest = None
    if manifest_file is not None:
        try:
            manifest = json.loads(manifest_file.getvalue())
        except ValueError:
            manifest = {}
    checks = conversion_checks(report, csv_hashes["sha256"], csv_file.name, dump_sha256, manifest)

    failed = [c for c in checks if c[0] is False]
    verdict = "FAILED" if failed else "VERIFIED"
    _log.log(logging.WARNING if failed else logging.INFO,
             f"CONVERSION CHECK | USER={_user()} | CSV={_clean(csv_file.name)} | CSV_SHA256={csv_hashes['sha256']} | "
             f"IMAGE_SHA256={pre.get('sha256', '-')} | RESULT={verdict}")
    ui.render_html(ui.banner("verified" if not failed else "gpp_bad",
                             "Conversion verified — memory image → CSV chain is intact" if not failed
                             else "Conversion NOT verified",
                             "Every check below passed." if not failed else
                             f"{len(failed)} check(s) failed — treat this CSV as unverified.",
                             "good" if not failed else "critical"))
    ui.render_html("".join(_step(*c) for c in checks))


# ── 3. Help ──────────────────────────────────────────────────────────────────
def _render_how_to():
    st.markdown("Get a file's hash yourself (run on the computer that holds the file):")
    st.dataframe(pd.DataFrame([
        {"System": "Windows (Command Prompt)", "Command": "certutil -hashfile <file> SHA256"},
        {"System": "Windows (PowerShell)", "Command": "Get-FileHash <file> -Algorithm SHA256"},
        {"System": "Linux / macOS", "Command": "sha256sum <file>    (or: shasum -a 256 <file>)"},
        {"System": "MD5 / SHA-1", "Command": "replace SHA256 with MD5 or SHA1 (md5sum / sha1sum on Linux)"},
    ]), hide_index=True, width="stretch")
    st.markdown("- **DumpIt, FTK Imager, WinPmem** print or log the image hash at acquisition — paste that log here.\n"
                "- HazMem writes a `.sha256` file next to every CSV and report it creates.\n"
                "- A **match** proves the file is bit-for-bit identical. A **mismatch** means a different, incomplete "
                "or altered file.")


def render_hash_checker_page():
    ui.section("Hash checker", "Prove a memory image, raw dump or CSV is exactly the expected file — before and "
                               "after conversion.", "fingerprint")
    t_file, t_conv, t_help = st.tabs([":material/fingerprint: Verify a file",
                                      ":material/swap_horiz: Verify dump → CSV conversion",
                                      ":material/help: How to get a hash"])
    with t_file:
        _render_file_check()
    with t_conv:
        _render_conversion_check()
    with t_help:
        _render_how_to()
