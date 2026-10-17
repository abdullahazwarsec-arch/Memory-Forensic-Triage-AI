"""
Forensic knowledge base: plain-English meanings of the 55 Volatility memory
features, incident-response actions per risk tier and small label helpers
used by the dashboard and the PDF report.
"""

import re


# ── SECTION 4: FORENSIC FEATURE DICTIONARY & HUMAN TRANSLATOR ────────────────
# Translates raw Volatility memory artifacts into plain English for non-technical users & analysts
FEATURE_MEANINGS = {
    "svcscan.nservices": {
        "title": "Windows System Services Count",
        "desc": "Number of background services registered in the system service database.",
        "danger": "Malware registers hidden services for persistence or disables security tools."
    },
    "svcscan.shared_process_services": {
        "title": "Shared Service Host Processes (svchost)",
        "desc": "Count of background services sharing standard Windows svchost.exe processes.",
        "danger": "Fileless malware hijacks legitimate svchost process pools to hide covert operations."
    },
    "svcscan.process_services": {
        "title": "Dedicated Process Services",
        "desc": "Windows services operating inside their own dedicated background processes.",
        "danger": "Unusual counts often reveal persistent backdoor utilities running as services."
    },
    "svcscan.kernel_drivers": {
        "title": "Kernel Driver Registrations",
        "desc": "System records tracking active Windows ring-0 kernel drivers.",
        "danger": "Rootkits load unsigned or vulnerable drivers to bypass all endpoint security controls."
    },
    "handles.avg_handles_per_proc": {
        "title": "Average Resource Handles per Process",
        "desc": "Rate of files, keys, and sockets actively accessed by running applications.",
        "danger": "Spikes indicate aggressive file enumeration, ransomware sweeps, or spyware data harvesting."
    },
    "handles.nhandles": {
        "title": "Total Open Resource Handles",
        "desc": "Overall volume of operating system resource handles allocated in memory.",
        "danger": "Massive handle counts reflect rapid filesystem traversals or memory leak exploits."
    },
    "handles.nfile": {
        "title": "Active File Access Handles",
        "desc": "Number of open file descriptors maintained across all running processes.",
        "danger": "Ransomware encrypting files or exfiltration utilities generate abnormal file handles."
    },
    "handles.nevent": {
        "title": "Thread Synchronization Events",
        "desc": "Internal Windows event signaling objects used for inter-thread coordination.",
        "danger": "Malware synchronization routines, command beacons, and injected loaders alter event counts."
    },
    "handles.nmutant": {
        "title": "Mutex (Mutant) Synchronization Objects",
        "desc": "Mutual exclusion objects used by software to ensure only one instance runs.",
        "danger": "Trojans and ransomware commonly register unique hardcoded Mutexes to avoid re-infection."
    },
    "handles.nsection": {
        "title": "Shared Memory Section Handles",
        "desc": "Shared memory mappings used to exchange data or execute shared code.",
        "danger": "Attackers map shared memory sections to inject shellcode across process boundaries."
    },
    "handles.nthread": {
        "title": "Active Execution Thread Handles",
        "desc": "System references to running CPU execution threads.",
        "danger": "High counts indicate thread injection, reflective loaders, or covert beacon loops."
    },
    "pslist.avg_threads": {
        "title": "Process Thread Concurrency Density",
        "desc": "Average execution threads running concurrently inside each active process.",
        "danger": "Atypical thread density points to injected shellcode, cryptominers, or active C2 beacons."
    },
    "pslist.nproc": {
        "title": "Total Active Process Count",
        "desc": "Number of active applications and background programs running in memory.",
        "danger": "Abnormal drops (killed security software) or spikes (malware tools) signal an intrusion."
    },
    "pslist.nppid": {
        "title": "Parent-Child Process Tree Hierarchy (PPID)",
        "desc": "Authentic parentage tree showing which application launched each child program.",
        "danger": "PPID spoofing disguises malicious tools to appear as if launched by legitimate Windows parents."
    },
    "malfind.ninjections": {
        "title": "Direct Memory Code Injections",
        "desc": "Executable memory regions detected floating in RAM with no file on the hard drive.",
        "danger": "Strongest indicator of fileless malware, Cobalt Strike beacons, or in-memory shellcode payloads."
    },
    "malfind.commitCharge": {
        "title": "Injected Memory Committed Pages",
        "desc": "Physical RAM pages committed to suspicious unbacked executable memory regions.",
        "danger": "Directly indicates the size and memory footprint of an active in-memory exploit."
    },
    "malfind.protection": {
        "title": "Executable Memory Permissions (PAGE_EXECUTE)",
        "desc": "Virtual memory regions marked with Read-Write-Execute (RWX) permissions.",
        "danger": "Self-modifying exploits and loaders require RWX permissions to unpack malware in memory."
    },
    "psxview.not_in_eprocess": {
        "title": "Hidden Unlinked Process (DKOM Rootkit)",
        "desc": "A process exists in low-level CPU scheduler memory but was unlinked from the official task list.",
        "danger": "Rootkits use Direct Kernel Object Manipulation (DKOM) to hide malware from Task Manager & antivirus."
    },
    "psxview.not_in_pspCidTable": {
        "title": "Process Hidden from Handle Table",
        "desc": "Process present in scheduler structures but omitted from the kernel CID handle table.",
        "danger": "High-stealth evasion technique designed to conceal active backdoor processes."
    },
    "ldrmodules.not_in_load": {
        "title": "Reflective DLL Module Injection",
        "desc": "A dynamic link library is executing in RAM without being registered in standard Windows load tables.",
        "danger": "Hallmark signature of reflective DLL injection running completely fileless in physical memory."
    },
    "ldrmodules.not_in_init": {
        "title": "Uninitialized Memory Module",
        "desc": "A code module mapped into memory without completing standard Windows OS initialization.",
        "danger": "Stealth module loading bypassing standard operating system safety checks."
    },
    "dlllist.avg_dlls_per_proc": {
        "title": "Average Loaded DLLs per Process",
        "desc": "Number of dynamic link library modules linked into active software.",
        "danger": "DLL search-order hijacking and side-loading attacks inflate loaded DLL counts."
    },
    "dlllist.ndlls": {
        "title": "Total Loaded DLL Modules",
        "desc": "Overall count of dynamic libraries mapped across all system memory spaces.",
        "danger": "Large variations indicate widespread library tampering across running utilities."
    },
    "callbacks.ncallbacks": {
        "title": "Kernel Callback Notification Routines",
        "desc": "Low-level system notification hooks registered by drivers to monitor OS events.",
        "danger": "Evasion modules and rootkits install callbacks to monitor or blind security scanners."
    },
    "callbacks.nanonymous": {
        "title": "Anonymous Kernel Callbacks",
        "desc": "Kernel callback pointers referencing raw memory not belonging to any known driver on disk.",
        "danger": "Severe rootkit indicator: malicious code executing directly within kernel space."
    }
}

def get_feature_info(raw_name: str) -> dict:
    """Returns human-friendly title, description, and threat context for any Volatility feature."""
    tokens = re.findall(r'[a-zA-Z][a-zA-Z0-9_\.]*', str(raw_name))
    clean = tokens[0] if tokens else str(raw_name).strip()
    clean_dot = clean.replace('_', '.')
    clean_under = clean.replace('.', '_')
    
    for key in (clean, clean_dot, clean_under):
        if key in FEATURE_MEANINGS:
            return FEATURE_MEANINGS[key]
            
    prefix = clean.split('.')[0].lower()
    fallbacks = {
        "svcscan": {
            "title": f"Windows Service Telemetry ({clean})",
            "desc": "Metrics tracking background Windows services and their host process configurations.",
            "danger": "Altered service telemetry may indicate persistence setups or stopped security tools."
        },
        "handles": {
            "title": f"Resource Handle Allocation ({clean})",
            "desc": "Telemetry measuring file, registry, and memory handle allocation rates.",
            "danger": "Unusual handle usage indicates aggressive file scanning, credential theft, or memory tampering."
        },
        "pslist": {
            "title": f"Process & Thread Hierarchy ({clean})",
            "desc": "Operating system process scheduling, execution threads, and task allocations.",
            "danger": "Irregularities reflect injected background processes, spoofed parentage, or hidden tools."
        },
        "malfind": {
            "title": f"Memory Injection Signature ({clean})",
            "desc": "Detection of executable memory regions lacking disk image backing.",
            "danger": "Hallmark sign of in-memory beacons, unpackers, or injected shellcode."
        },
        "callbacks": {
            "title": f"Kernel Callback Routine ({clean})",
            "desc": "Low-level event notification routines registered with the Windows kernel.",
            "danger": "Rogue callbacks are employed by rootkits to evade AV detection or blind endpoint sensors."
        },
        "dlllist": {
            "title": f"Dynamic Link Library (DLL) Telemetry ({clean})",
            "desc": "Dynamic shared libraries loaded into process memory spaces.",
            "danger": "Deviations indicate module hijacking, rogue DLL injection, or sideloaded malware."
        },
        "ldrmodules": {
            "title": f"Module Loader Tracking ({clean})",
            "desc": "Internal Windows loader tables accounting for active process modules.",
            "danger": "Unlinked modules indicate reflective code injection running completely in physical RAM."
        },
        "psxview": {
            "title": f"Cross-View Process Inspection ({clean})",
            "desc": "Multi-table cross-validation of active processes to detect unlinked rootkits.",
            "danger": "Discrepancies indicate hidden processes obscured via Direct Kernel Object Manipulation (DKOM)."
        }
    }
    
    if prefix in fallbacks:
        return fallbacks[prefix]
        
    return {
        "title": f"Memory Artifact: {clean}",
        "desc": f"Observed variance in RAM telemetry metric '{clean}'.",
        "danger": "Telemetry value deviates from verified clean baseline operating parameters."
    }

# Risk-level colours used in Streamlit status boxes
RISK_COLOURS = {
    "HIGH RISK":   "red",
    "SUSPICIOUS":  "orange",
    "NORMAL":      "green",
}

# Incident response recommendations per risk tier
# One set of thresholds for everything shown to the user (risk tier and classification),
# so a result can never read "Suspicious" and "Malware" at the same time.
HIGH_RISK_AT, SUSPICIOUS_AT = 0.75, 0.40
CLASSIFICATION = {"HIGH RISK": "MALWARE", "SUSPICIOUS": "UNCERTAIN", "NORMAL": "BENIGN"}


def risk_tier(probability: float) -> str:
    """Malware probability -> "HIGH RISK" (>= 75 %), "SUSPICIOUS" (40-75 %) or "NORMAL" (< 40 %)."""
    if probability >= HIGH_RISK_AT:
        return "HIGH RISK"
    return "SUSPICIOUS" if probability >= SUSPICIOUS_AT else "NORMAL"


# The same advice in everyday words (shown in the simple view)
SIMPLE_ACTIONS = {
    "HIGH RISK": [
        "Disconnect the computer from the network now",
        "Do not switch it off - the memory evidence would be lost",
        "Tell your security team and send them the PDF report",
        "Keep the original memory file safe and unchanged",
    ],
    "SUSPICIOUS": [
        "Ask a security analyst to review this computer before it is used again",
        "Keep it away from sensitive systems until it has been reviewed",
        "Send the PDF report to the person handling the case",
    ],
    "NORMAL": [
        "No action is needed",
        "Keep the PDF report with the case for your records",
    ],
}


def plain_name(indicator: str) -> str:
    """'Cross-View Process Inspection (psxview.not_in_deskthrd)' -> 'Cross-View Process Inspection'."""
    return re.sub(r"\s*\([^)]*\)\s*$", "", str(indicator)).strip()


RESPONSE_ACTIONS = {
    "HIGH RISK": [
        "🔴 Isolate endpoint from network immediately",
        "🔴 Preserve full memory dump using Volatility3 or WinPmem",
        "🔴 Extract and hash all injected process regions",
        "🔴 Escalate to Tier 2 analyst and open incident ticket",
        "🔴 Correlate with SIEM and threat intelligence feeds",
    ],
    "SUSPICIOUS": [
        "🟡 Do NOT take automated action — human review required",
        "🟡 Run additional Volatility plugins: malfind, pstree, netscan",
        "🟡 Compare process tree against known-good baseline",
        "🟡 Submit sample to sandbox (Any.run / Hybrid Analysis)",
    ],
    "NORMAL": [
        "🟢 No immediate action required",
        "🟢 Continue standard monitoring schedule",
        "🟢 Archive this triage result for baseline comparison",
    ],
}


def recipient_label(recipient: dict) -> str:
    name, org = recipient.get("name", ""), recipient.get("organisation", "")
    return f"{name} ({org})" if name and org else name or org or "-"


def origin_label(origin: dict) -> str:
    who = f" (custodian: {origin['custodian']})" if origin.get("custodian") else ""
    return f"{origin.get('source_device', '-')}{who}"
