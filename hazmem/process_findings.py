"""
Per-process findings from the saved Volatility 3 output.

The ML verdict only sees 55 whole-system counts, so it cannot say *which* process looks wrong.
This module re-reads the same plugin output and applies well-known memory-forensics checks to
every process, so an analyst knows where to start:

  hidden process       in the psscan pool scan but missing from the active list (DKOM rootkits)
  injected executable  malfind region that starts with an "MZ" PE header (process hollowing / injection)
  injected code        writable + executable private memory that contains code
  RWX memory           writable + executable private memory that is empty (often harmless: .NET/JIT)
  hidden DLL           a .dll from outside the Windows folders, mapped but missing from all three loader lists
                       (resource-only DLLs from System32 are routinely unlisted, so they are ignored)
  wrong parent         a core Windows process started by the wrong parent, or a second copy of one
  look-alike name      a name one letter away from a core Windows process (svch0st.exe)
  wrong folder         a core Windows process name running from outside System32, or anything from Temp/AppData

These are leads for a human, not proof: legitimate software can trip the weaker checks.
"""
import json
import os

import pandas as pd

FINDINGS_FILE = "process_findings.json"

# (points, plain-English label, technical detail); >= 3 points makes a process "High"
WEIGHTS = {"hidden": 3, "pe": 3, "code": 2, "rwx": 1, "dll": 2, "parent": 2, "lookalike": 3, "folder": 2, "userdir": 1}
LEVELS = [(3, "High"), (2, "Medium"), (1, "Low")]

EXPECTED_PARENT = {"svchost.exe": "services.exe", "services.exe": "wininit.exe", "lsass.exe": "wininit.exe",
                   "lsaiso.exe": "wininit.exe", "smss.exe": "System"}
SINGLE_INSTANCE = {"lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe"}
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe", "smss.exe", "wininit.exe",
                "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe", "lsaiso.exe",
                "explorer.exe", "taskmgr.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
                "searchindexer.exe", "wmiprvse.exe", "msmpeng.exe", "userinit.exe", "regsvr32.exe",
                # older / other genuine names, so they are not mistaken for look-alikes
                "taskhost.exe", "taskeng.exe", "lsm.exe", "audiodg.exe", "sppsvc.exe", "msdtc.exe", "wuauclt.exe",
                "searchprotocolhost.exe", "searchfilterhost.exe", "wmpnetwk.exe", "smartscreen.exe",
                "runtimebroker.exe", "svchost.exe", "dashost.exe", "mscorsvw.exe", "vmtoolsd.exe", "vmacthlp.exe"}
SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\")
WINDOWS_DIRS = ("\\windows\\",)
USER_DIRS = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\", "\\programdata\\")


def _flatten(rows):
    flat = []
    for r in rows or []:
        r = dict(r)
        children = r.pop("__children", []) or []
        flat.append(r)
        flat.extend(_flatten(children))
    return flat


def _frame(plugin_rows, name):
    return pd.DataFrame(_flatten(plugin_rows.get(f"windows.{name}") or plugin_rows.get(name) or []))


def _true(series):
    return series.astype(str).str.lower() == "true"


def _alive(series):
    """Exit-time column -> True where the process has not exited."""
    text = series.astype(str).str.strip().str.lower()
    return series.isna() | text.isin(["", "none", "n/a", "nan", "nat"])


def _distance(a, b):
    """Levenshtein distance (names are short)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _norm_path(path):
    """Lower-case path with \\SystemRoot\\ resolved to \\windows\\."""
    return str(path).lower().replace("\\systemroot\\", "\\windows\\")


def _lookalike(name):
    """The core Windows process this name imitates, if it is one edit away from it (names truncate at 14)."""
    if name in SYSTEM_NAMES or len(name) < 6:
        return None
    for real in SYSTEM_NAMES:
        target = real[:len(name)] if len(name) == 14 else real
        if name != target and _distance(name, target) <= (1 if len(target) < 10 else 2):
            return real
    return None


def find_suspicious_processes(plugin_rows: dict) -> list:
    """{plugin: rows} (as Volatility's JSON renderer returns them) -> processes with findings, worst first."""
    pslist, malfind = _frame(plugin_rows, "pslist"), _frame(plugin_rows, "malfind")
    psxview, ldr, dlls = _frame(plugin_rows, "psxview"), _frame(plugin_rows, "ldrmodules"), _frame(plugin_rows, "dlllist")
    procs, reasons = {}, {}

    def note(pid, name, key, text, detail=""):
        pid = int(pid)
        procs.setdefault(pid, {"pid": pid, "name": str(name), "ppid": None})
        reasons.setdefault(pid, {})
        reasons[pid].setdefault(key, (text, detail))

    names = {}
    if not pslist.empty:
        alive = pslist[_alive(pslist["ExitTime"])] if "ExitTime" in pslist else pslist
        for _, r in pslist.iterrows():
            names[int(r["PID"])] = str(r["ImageFileName"])
        for _, r in alive.iterrows():
            pid, name = int(r["PID"]), str(r["ImageFileName"]).lower()
            parent = names.get(int(r["PPID"]), "").lower() if pd.notna(r["PPID"]) else ""
            expected = EXPECTED_PARENT.get(name)
            if expected and parent and parent != expected.lower():
                note(pid, r["ImageFileName"], "parent", f"Started by {names.get(int(r['PPID']))}, "
                     f"but Windows always starts {name} from {expected}", f"PPID {int(r['PPID'])}")
            if name in SINGLE_INSTANCE and (alive["ImageFileName"].str.lower() == name).sum() > 1:
                note(pid, r["ImageFileName"], "parent", f"More than one {name} is running (Windows runs only one)")
            real = _lookalike(name)
            if real:
                note(pid, r["ImageFileName"], "lookalike", f"Name imitates the Windows process {real}")

    if not psxview.empty:
        px = psxview.assign(pslist=_true(psxview["pslist"]), psscan=_true(psxview["psscan"]),
                            alive=_alive(psxview["Exit Time"]) if "Exit Time" in psxview else True)
        grouped = px.groupby(["PID", "Name"]).agg(pslist=("pslist", "any"), psscan=("psscan", "any"),
                                                 alive=("alive", "all")).reset_index()
        for _, r in grouped[grouped["psscan"] & ~grouped["pslist"] & grouped["alive"]].iterrows():
            note(r["PID"], r["Name"], "hidden", "Hidden from the normal process list (rootkit technique)",
                 "psscan yes, pslist no")

    if not malfind.empty:
        for _, r in malfind.iterrows():
            hexdump = str(r.get("Hexdump", "")).lower().replace("\n", " ").split()
            detail = f"{r.get('Protection', '')} at {r.get('Start VPN', '')}"
            # several regions per process are common: one finding per kind, the weaker ones dropped below
            if hexdump[:2] == ["4d", "5a"]:
                note(r["PID"], r["Process"], "pe", "A whole program (PE file) was injected into its memory", detail)
            elif hexdump and any(b != "00" for b in hexdump):
                note(r["PID"], r["Process"], "code", "Code was written into memory that can also be run "
                     "(possible code injection)", detail)
            else:
                note(r["PID"], r["Process"], "rwx", "Has writable and runnable memory (often harmless, "
                     "e.g. .NET programs)", detail)

    if not ldr.empty:
        mapped = ldr["MappedPath"].astype(str).map(_norm_path)
        outside = ~mapped.map(lambda m: any(d in m for d in WINDOWS_DIRS))
        hidden = ldr[mapped.str.endswith(".dll") & outside
                     & ~(_true(ldr["InLoad"]) | _true(ldr["InInit"]) | _true(ldr["InMem"]))]
        for pid, group in hidden.groupby("Pid"):
            first = os.path.basename(group["MappedPath"].astype(str).iloc[0].replace("\\", "/"))
            more = f" and {len(group) - 1} more" if len(group) > 1 else ""
            note(pid, group["Process"].iloc[0], "dll", "A DLL is loaded but hidden from Windows' module lists",
                 f"{first}{more}")

    if not dlls.empty and "Path" in dlls:
        for pid, group in dlls.groupby("PID"):
            path = str(group["Path"].iloc[0])
            name, lower = str(group["Process"].iloc[0]).lower(), _norm_path(path)
            if not lower.endswith(".exe"):
                continue
            if name in SYSTEM_NAMES - {"explorer.exe", "msmpeng.exe"} and not any(d in lower for d in SYSTEM_DIRS):
                note(pid, group["Process"].iloc[0], "folder", f"Windows process name, but runs from {path}")
            elif any(d in lower for d in USER_DIRS):
                note(pid, group["Process"].iloc[0], "userdir", f"Runs from a user folder ({path})")

    parents = {}
    if not pslist.empty:
        parents = {int(r["PID"]): int(r["PPID"]) for _, r in pslist.iterrows() if pd.notna(r["PPID"])}

    findings = []
    for pid, info in procs.items():
        info["ppid"] = parents.get(pid)
        keys = reasons.get(pid, {})
        if "pe" in keys or "code" in keys:
            keys.pop("rwx", None)
        if "pe" in keys:
            keys.pop("code", None)
        score = sum(WEIGHTS[k] for k in keys)
        level = next(label for minimum, label in LEVELS if score >= minimum)
        findings.append({**info, "name": names.get(pid, info["name"]), "score": score, "level": level,
                         "checks": sorted(keys, key=lambda k: -WEIGHTS[k]),
                         "reasons": [keys[k][0] for k in sorted(keys, key=lambda k: -WEIGHTS[k])],
                         "details": [keys[k][1] for k in sorted(keys, key=lambda k: -WEIGHTS[k]) if keys[k][1]]})
    return sorted(findings, key=lambda f: (-f["score"], f["pid"]))


def load_plugin_output(folder: str) -> dict:
    """Read the windows.<plugin>.json files the extractor saved in an extraction folder."""
    rows = {}
    for name in ("pslist", "malfind", "psxview", "ldrmodules", "dlllist"):
        path = os.path.join(folder, f"windows.{name}.json")
        try:
            with open(path, encoding="utf-8") as f:
                rows[f"windows.{name}"] = json.load(f)
        except (OSError, ValueError):
            rows[f"windows.{name}"] = []
    return rows


def summary(findings: list) -> dict:
    return {level: sum(f["level"] == level for f in findings) for _, level in LEVELS}
