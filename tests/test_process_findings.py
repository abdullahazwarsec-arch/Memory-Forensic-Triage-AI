"""Per-process checks on Volatility 3 output (rows shaped like its JSON renderer)."""

import json

from hazmem import process_findings as pf


def proc(pid, name, ppid, exited=None):
    return {"PID": pid, "PPID": ppid, "ImageFileName": name, "ExitTime": exited, "Threads": 5, "Handles": 50}


BASE = [proc(4, "System", 0), proc(300, "smss.exe", 4), proc(500, "wininit.exe", 400),
        proc(600, "services.exe", 500), proc(650, "lsass.exe", 500), proc(700, "svchost.exe", 600),
        proc(900, "explorer.exe", 880)]


def run(pslist=None, **plugins):
    rows = {"windows.pslist": BASE + (pslist or [])}
    rows.update({f"windows.{k}": v for k, v in plugins.items()})
    return {f["pid"]: f for f in pf.find_suspicious_processes(rows)}


def test_clean_system_has_no_findings():
    assert run() == {}


def test_wrong_parent_duplicate_and_lookalike():
    found = run([proc(1200, "svchost.exe", 900), proc(1300, "lsass.exe", 900), proc(1400, "svch0st.exe", 600)])
    assert found[1200]["checks"] == ["parent"] and found[1200]["ppid"] == 900
    assert "parent" in found[1300]["checks"] and "parent" in found[650]["checks"]   # two lsass.exe
    assert found[1400]["checks"] == ["lookalike"] and found[1400]["level"] == "High"


def test_exited_duplicates_are_ignored():
    assert run([proc(1300, "lsass.exe", 500, exited="2024-01-01 10:00:00")]) == {}


def test_hidden_process_merges_offset_rows_and_skips_exited():
    psx = [{"PID": 1500, "Name": "evil.exe", "pslist": False, "psscan": True, "thrdscan": True, "csrss": False,
            "Exit Time": None},
           {"PID": 700, "Name": "svchost.exe", "pslist": False, "psscan": True, "thrdscan": True, "csrss": True,
            "Exit Time": None},                                    # physical-offset copy of a listed process
           {"PID": 700, "Name": "svchost.exe", "pslist": True, "psscan": True, "thrdscan": True, "csrss": True,
            "Exit Time": None},
           {"PID": 1600, "Name": "old.exe", "pslist": False, "psscan": True, "thrdscan": False, "csrss": False,
            "Exit Time": "2024-01-01 09:00:00"}]
    found = run(psxview=psx)
    assert list(found) == [1500] and found[1500]["level"] == "High"


def test_malfind_grades_regions_and_keeps_the_strongest():
    region = lambda pid, hexdump: {"PID": pid, "Process": "x.exe", "Protection": "PAGE_EXECUTE_READWRITE",  # noqa: E731
                                   "Start VPN": 4096, "Hexdump": hexdump}
    found = run(malfind=[region(900, "4d 5a 90 00 03 00"), region(900, "00 00 00 00"), region(700, "55 8b ec 00"),
                         region(700, "00 00 00 00"), region(650, "00 00\n00 00")])
    assert found[900]["checks"] == ["pe"] and found[900]["level"] == "High"
    assert found[700]["checks"] == ["code"] and found[700]["level"] == "Medium"
    assert found[650]["checks"] == ["rwx"] and found[650]["level"] == "Low"


def test_hidden_dll_ignores_windows_resource_dlls():
    row = lambda path: {"Pid": 900, "Process": "explorer.exe", "Base": 1, "InLoad": False,  # noqa: E731
                        "InInit": False, "InMem": False, "MappedPath": path}
    assert run(ldrmodules=[row(r"\Windows\System32\oleaccrc.dll"), row(r"\Windows\System32\en-US\a.dll.mui")]) == {}
    found = run(ldrmodules=[row(r"\Users\bob\AppData\Roaming\inject.dll"), row(r"\ProgramData\x.dll")])
    assert found[900]["checks"] == ["dll"] and "inject.dll and 1 more" in found[900]["details"][0]


def test_executable_location():
    dll = lambda pid, name, path: {"PID": pid, "Process": name, "Path": path, "Name": name}  # noqa: E731
    found = run(dlllist=[dll(300, "smss.exe", r"\SystemRoot\System32\smss.exe"),
                         dll(700, "svchost.exe", r"C:\Users\Public\svchost.exe"),
                         dll(900, "explorer.exe", r"C:\Windows\explorer.exe"),
                         dll(1700, "tool.exe", r"C:\Users\bob\Downloads\tool.exe")], pslist=[proc(1700, "tool.exe", 900)])
    assert set(found) == {700, 1700}
    assert found[700]["checks"] == ["folder"] and found[1700]["checks"] == ["userdir"]


def test_findings_are_sorted_and_summarised():
    found = pf.find_suspicious_processes({"windows.pslist": BASE + [proc(1400, "svch0st.exe", 600),
                                                                    proc(1200, "svchost.exe", 900)]})
    assert [f["pid"] for f in found] == [1400, 1200]
    assert pf.summary(found) == {"High": 1, "Medium": 1, "Low": 0}


def test_nested_children_and_saved_output(tmp_path):
    nested = [dict(proc(600, "services.exe", 500), __children=[proc(1200, "svchost.exe", 900)])]
    (tmp_path / "windows.pslist.json").write_text(json.dumps(BASE + nested), encoding="utf-8")
    (tmp_path / "windows.malfind.json").write_text("not json", encoding="utf-8")    # damaged file is skipped
    rows = pf.load_plugin_output(str(tmp_path))
    assert rows["windows.malfind"] == [] and 1200 in {f["pid"] for f in pf.find_suspicious_processes(rows)}
    assert "__children" in rows["windows.pslist"][-1]          # input rows are not modified
