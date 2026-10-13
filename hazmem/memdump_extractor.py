"""
Memory Dump → Feature CSV Extractor
===================================
Runs Volatility 3 plugins against a raw Windows memory image (.raw / .mem /
.vmem / .dmp ...) and converts the plugin output into the same 55 features
used by the CIC-MalMem2022 dataset the triage models were trained on.

Usage (CLI):
    python memdump_extractor.py <memory_dump> [--out <dir>]

The resulting CSV can be fed straight into the Streamlit triage dashboard.
"""

import os
import sys
import json
import shutil
import subprocess
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

from .evidence_integrity import hash_file, write_hash_sidecar


BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # project root
EXTRACT_DIR   = os.path.join(BASE_DIR, "outputs", "extracted")
DUMP_EXTENSIONS = ["raw", "mem", "vmem", "dmp", "bin", "img", "lime", "dump"]

# Volatility 3 plugins required to build the 55 CIC-MalMem2022 features
PLUGINS = [
    "windows.pslist", "windows.dlllist", "windows.handles", "windows.ldrmodules",
    "windows.malfind", "windows.psxview", "windows.modules", "windows.svcscan",
    "windows.callbacks",
]

# Feature order expected by the trained models
FEATURE_COLUMNS = [
    "pslist.nproc", "pslist.nppid", "pslist.avg_threads", "pslist.nprocs64bit", "pslist.avg_handlers",
    "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
    "handles.nhandles", "handles.avg_handles_per_proc", "handles.nport", "handles.nfile", "handles.nevent",
    "handles.ndesktop", "handles.nkey", "handles.nthread", "handles.ndirectory", "handles.nsemaphore",
    "handles.ntimer", "handles.nsection", "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
    "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
    "malfind.ninjections", "malfind.commitCharge", "malfind.protection", "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool", "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list", "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg", "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg", "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg", "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "modules.nmodules",
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers", "svcscan.process_services",
    "svcscan.shared_process_services", "svcscan.interactive_process_services", "svcscan.nactive",
    "callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric",
]

# Numeric VAD protection codes (MMVAD protection index). The dataset's
# malfind.protection column is the sum of these codes over all injections.
VAD_PROTECTION_CODES = {
    "PAGE_NOACCESS": 0, "PAGE_READONLY": 1, "PAGE_EXECUTE": 2, "PAGE_EXECUTE_READ": 3,
    "PAGE_READWRITE": 4, "PAGE_WRITECOPY": 5, "PAGE_EXECUTE_READWRITE": 6,
    "PAGE_EXECUTE_WRITECOPY": 7,
}


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class ExtractionError(Exception):
    """Raised when the memory image cannot be processed."""


# ── Volatility execution ──────────────────────────────────────────────────────
def _vol_command():
    """Volatility 3 CLI invocation, preferring the environment running this code."""
    scripts_dir = os.path.dirname(sys.executable)
    for name in ("vol.exe", "vol"):
        candidate = os.path.join(scripts_dir, name)
        if os.path.isfile(candidate):
            return [candidate]
    try:
        import volatility3  # noqa: F401
        return [sys.executable, "-c",
                "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()"]
    except ImportError:
        vol = shutil.which("vol") or shutil.which("vol.py")
        if vol:
            return [vol]
    raise ExtractionError("Volatility 3 is not installed. Run: pip install volatility3")


def _run_plugin(dump_path: str, plugin: str, out_dir: str, timeout: int = 3600) -> list:
    """Run one Volatility plugin with the JSON renderer; save and return its rows."""
    cmd = _vol_command() + ["-q", "-r", "json", "-f", dump_path, plugin]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)
    json_path = os.path.join(out_dir, f"{plugin}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(proc.stdout)
    if proc.returncode != 0 or not proc.stdout.strip():
        err = (proc.stderr or "").strip().splitlines()
        raise ExtractionError(f"{plugin} failed: {err[-1] if err else 'no output'}")
    return json.loads(proc.stdout)


def _flatten(rows: list) -> list:
    """Volatility JSON nests child rows under '__children'; flatten them."""
    flat = []
    for r in rows:
        children = r.pop("__children", []) or []
        flat.append(r)
        flat.extend(_flatten(children))
    return flat


# ── Feature engineering (mirrors VolMemLyzer / CIC-MalMem2022) ────────────────
def _is_true(series: pd.Series) -> pd.Series:
    return series.astype(str).str.lower() == "true"


def _safe_div(a, b):
    return float(a) / float(b) if b else 0.0


def _pslist_features(df):
    if df.empty:
        return {}
    return {
        "pslist.nproc":        len(df),
        "pslist.nppid":        df["PPID"].nunique(),
        "pslist.avg_threads":  pd.to_numeric(df["Threads"], errors="coerce").mean(),
        "pslist.nprocs64bit":  int(_is_true(df["Wow64"]).sum()) if "Wow64" in df else 0,
        "pslist.avg_handlers": pd.to_numeric(df["Handles"], errors="coerce").mean(),
    }


def _dlllist_features(df):
    if df.empty:
        return {}
    return {
        "dlllist.ndlls":             len(df),
        "dlllist.avg_dlls_per_proc": _safe_div(len(df), df["PID"].nunique()),
    }


def _handles_features(df):
    if df.empty:
        return {}
    types = df["Type"].astype(str)
    feats = {
        "handles.nhandles":             len(df),
        "handles.avg_handles_per_proc": _safe_div(len(df), df["PID"].nunique()),
    }
    # Exact type names, as in the original dataset extraction
    for feat, type_name in [("nport", "Port"), ("nfile", "File"), ("nevent", "Event"),
                            ("ndesktop", "Desktop"), ("nkey", "Key"), ("nthread", "Thread"),
                            ("ndirectory", "Directory"), ("nsemaphore", "Semaphore"),
                            ("ntimer", "Timer"), ("nsection", "Section"), ("nmutant", "Mutant")]:
        feats[f"handles.{feat}"] = int((types == type_name).sum())
    return feats


def _ldrmodules_features(df):
    if df.empty:
        return {}
    feats = {}
    for feat, col in [("not_in_load", "InLoad"), ("not_in_init", "InInit"), ("not_in_mem", "InMem")]:
        missing = int((~_is_true(df[col])).sum())
        feats[f"ldrmodules.{feat}"]     = missing
        feats[f"ldrmodules.{feat}_avg"] = _safe_div(missing, len(df))
    return feats


def _malfind_features(df):
    if df.empty:
        return {"malfind.ninjections": 0, "malfind.commitCharge": 0,
                "malfind.protection": 0, "malfind.uniqueInjections": 0}
    return {
        "malfind.ninjections":      len(df),
        "malfind.commitCharge":     pd.to_numeric(df["CommitCharge"], errors="coerce").fillna(0).sum(),
        "malfind.protection":       df["Protection"].map(VAD_PROTECTION_CODES).fillna(0).sum(),
        "malfind.uniqueInjections": _safe_div(len(df), df["PID"].nunique()),
    }


def _psxview_features(df, pslist_df):
    if df.empty:
        return {}
    views = ["pslist", "psscan", "thrdscan", "csrss"]
    df = df.copy()
    for v in views:
        df[v] = _is_true(df[v])
    # Volatility 3 lists a live process once per offset type (virtual vs physical);
    # merge those duplicate rows so each process is counted once.
    procs = df.groupby(["PID", "Name"])[views].any().reset_index()
    n = len(procs)

    # Volatility 3 psxview has no pspcid/session/deskthrd views; derive them:
    #   pspcid  ≈ pslist view (both enumerate active processes)
    #   session = processes with a session id in pslist (System/smss have none)
    #   deskthrd ≈ csrss view (GUI processes own desktop threads + csrss handles)
    session_pids = set()
    if not pslist_df.empty and "SessionId" in pslist_df:
        sess = pslist_df[pd.to_numeric(pslist_df["SessionId"], errors="coerce").notna()]
        session_pids = set(sess["PID"])
    procs["pspcid"]   = procs["pslist"]
    procs["session"]  = procs["PID"].isin(session_pids)
    procs["deskthrd"] = procs["csrss"]

    feats = {}
    for feat, col in [("pslist", "pslist"), ("eprocess_pool", "psscan"),
                      ("ethread_pool", "thrdscan"), ("pspcid_list", "pspcid"),
                      ("csrss_handles", "csrss"), ("session", "session"),
                      ("deskthrd", "deskthrd")]:
        missing = int((~procs[col]).sum())
        feats[f"psxview.not_in_{feat}"]           = missing
        feats[f"psxview.not_in_{feat}_false_avg"] = _safe_div(missing, n)
    return feats


def _modules_features(df):
    return {"modules.nmodules": len(df)}


def _svcscan_features(df):
    if df.empty:
        return {}
    # svcscan carves service records and returns many duplicates; keep one per record
    key = "Offset" if "Offset" in df else "Name"
    df = df.drop_duplicates(key)
    types = df["Type"].astype(str)
    return {
        "svcscan.nservices":                    len(df),
        "svcscan.kernel_drivers":               int((types == "SERVICE_KERNEL_DRIVER").sum()),
        "svcscan.fs_drivers":                   int((types == "SERVICE_FILE_SYSTEM_DRIVER").sum()),
        "svcscan.process_services":             int((types == "SERVICE_WIN32_OWN_PROCESS").sum()),
        "svcscan.shared_process_services":      int((types == "SERVICE_WIN32_SHARE_PROCESS").sum()),
        "svcscan.interactive_process_services": int((types == "SERVICE_INTERACTIVE_PROCESS").sum()),
        "svcscan.nactive":                      int((df["State"].astype(str) == "SERVICE_RUNNING").sum()),
    }


def _callbacks_features(df):
    if df.empty:
        return {"callbacks.ncallbacks": 0, "callbacks.nanonymous": 0, "callbacks.ngeneric": 0}
    module = df["Module"].astype(str)
    return {
        "callbacks.ncallbacks": len(df),
        "callbacks.nanonymous": int(module.isin(["UNKNOWN", "Unknown"]).sum()),
        "callbacks.ngeneric":   int((df["Type"].astype(str) == "GenericKernelCallback").sum()),
    }


def build_features(plugin_rows: dict) -> pd.DataFrame:
    """Convert {plugin_name: rows} into a single-row DataFrame of the 55 features."""
    frames = {p.split(".")[-1]: pd.DataFrame(_flatten(list(rows or [])))
              for p, rows in plugin_rows.items()}
    get = lambda name: frames.get(name, pd.DataFrame())

    feats = {}
    feats.update(_pslist_features(get("pslist")))
    feats.update(_dlllist_features(get("dlllist")))
    feats.update(_handles_features(get("handles")))
    feats.update(_ldrmodules_features(get("ldrmodules")))
    feats.update(_malfind_features(get("malfind")))
    feats.update(_psxview_features(get("psxview"), get("pslist")))
    feats.update(_modules_features(get("modules")))
    feats.update(_svcscan_features(get("svcscan")))
    feats.update(_callbacks_features(get("callbacks")))

    row = {col: float(feats.get(col, 0) or 0) for col in FEATURE_COLUMNS}
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)


# ── Public entry point ────────────────────────────────────────────────────────
def extract_features(dump_path: str, out_dir: str = None, progress_cb=None, max_workers: int = 3):
    """
    Extract the 55 memory features from a Windows memory dump.

    Returns (features_df, csv_path, report) where report holds OS info,
    per-plugin timings/status, warnings and an "integrity" section with the
    dump's hashes taken immediately before and after Volatility processing
    (proving the evidence was not modified) plus the hash of the derived CSV.
    """
    if not os.path.isfile(dump_path):
        raise ExtractionError(f"Memory dump not found: {dump_path}")

    dump_name = os.path.splitext(os.path.basename(dump_path))[0]
    if out_dir is None:
        stamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.join(EXTRACT_DIR, f"{dump_name}_{stamp}")
    os.makedirs(out_dir, exist_ok=True)

    report = {"dump": os.path.abspath(dump_path), "output_dir": out_dir,
              "os_info": {}, "plugins": {}, "warnings": [], "integrity": {}}
    progress = progress_cb or (lambda frac, msg: None)
    total_steps = len(PLUGINS) + 1

    # Step 0: integrity baseline of the memory image before any processing
    progress(0.0, "Hashing memory image before extraction (SHA-256 + MD5)...")
    report["integrity"]["pre_extraction"] = dict(hash_file(
        dump_path, progress=lambda done, total: progress(0.0, f"Hashing memory image before extraction... "
                                                              f"{done * 100 // max(total, 1)}%")), utc=_utc())

    # Step 1: identify the OS profile (also downloads/caches kernel symbols once)
    progress(0.0, "Identifying Windows kernel & resolving symbols (windows.info)...")
    started = datetime.now()
    try:
        info_rows = _run_plugin(dump_path, "windows.info", out_dir)
    except ExtractionError as e:
        raise ExtractionError(
            "Volatility could not identify a Windows kernel in this image. "
            "Make sure it is a raw Windows memory dump and that the machine has internet "
            f"access on first use (to download symbol tables). Details: {e}"
        )
    report["os_info"] = {r.get("Variable"): r.get("Value") for r in _flatten(info_rows)}
    report["plugins"]["windows.info"] = {"status": "ok", "rows": len(info_rows),
                                         "seconds": (datetime.now() - started).total_seconds()}

    # Step 2: run the feature plugins in parallel
    def _timed_run(plugin):
        t0 = datetime.now()
        rows = _run_plugin(dump_path, plugin, out_dir)
        return rows, (datetime.now() - t0).total_seconds()

    plugin_rows, done = {}, 1
    progress(done / total_steps, "Running Volatility plugins...")
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_timed_run, p): p for p in PLUGINS}
        for fut in as_completed(futures):
            plugin = futures[fut]
            try:
                plugin_rows[plugin], seconds = fut.result()
                report["plugins"][plugin] = {"status": "ok", "rows": len(plugin_rows[plugin]),
                                             "seconds": seconds}
            except Exception as e:
                plugin_rows[plugin] = []
                report["plugins"][plugin] = {"status": "failed", "error": str(e)}
                report["warnings"].append(f"{plugin} failed – its features were set to 0 ({e})")
            done += 1
            progress(done / total_steps, f"Finished {plugin}")

    if all(v["status"] == "failed" for k, v in report["plugins"].items() if k != "windows.info"):
        raise ExtractionError("Every Volatility plugin failed; no features could be extracted.")

    # Step 3: re-hash the image to prove Volatility did not alter the evidence
    progress(0.97, "Re-hashing memory image after extraction (integrity verification)...")
    pre  = report["integrity"]["pre_extraction"]
    post = dict(hash_file(
        dump_path, progress=lambda done, total: progress(0.97, f"Re-hashing memory image after extraction... "
                                                               f"{done * 100 // max(total, 1)}%")), utc=_utc())
    report["integrity"]["post_extraction"] = post
    report["integrity"]["dump_unchanged"]  = post["sha256"] == pre["sha256"]
    if not report["integrity"]["dump_unchanged"]:
        report["warnings"].append("INTEGRITY ALERT: memory image hash changed during extraction!")

    # Step 4: build feature row, save CSV and fingerprint it
    features = build_features(plugin_rows)
    csv_path = os.path.join(out_dir, f"{dump_name}_features.csv")
    features.to_csv(csv_path, index=False)
    csv_hashes = hash_file(csv_path)
    write_hash_sidecar(csv_path, csv_hashes)
    report["integrity"]["derived_csv"] = dict(csv_hashes, utc=_utc(), file=os.path.basename(csv_path))
    with open(os.path.join(out_dir, "extraction_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    progress(1.0, "Feature extraction complete")
    return features, csv_path, report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extract CIC-MalMem2022 features from a memory dump")
    parser.add_argument("dump", help="Path to the raw Windows memory image")
    parser.add_argument("--out", help="Output directory (default: outputs/extracted/<dump>_<time>)")
    args = parser.parse_args()

    def _print_progress(frac, msg):
        print(f"[{frac * 100:5.1f}%] {msg}", flush=True)

    try:
        df, path, rep = extract_features(args.dump, args.out, _print_progress)
    except ExtractionError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
    for w in rep["warnings"]:
        print(f"[WARN] {w}")
    integ = rep["integrity"]
    print(f"\n[+] Dump SHA-256 (before): {integ['pre_extraction']['sha256']}")
    print(f"[+] Dump SHA-256 (after) : {integ['post_extraction']['sha256']}  "
          f"-> {'UNCHANGED' if integ['dump_unchanged'] else 'MODIFIED!'}")
    print(f"[+] CSV  SHA-256         : {integ['derived_csv']['sha256']}")
    print(f"\n[+] Features saved to: {path}")
    print(df.T.to_string(header=False))
