"""
MemTriage XAI - explainable AI triage for Windows memory forensics.

Supporting package for the Streamlit dashboard (app.py):

    evidence_integrity   hashing, HMAC-keyed chain-of-custody ledger, model hash pinning
    audit_log            HMAC-chained, tamper-evident audit log (+ archive / verify CLI)
    input_validation     intake gates (size, CSV structure, memory-image signatures) and feature gate
    memdump_extractor    Volatility 3 memory dump -> 55-feature CSV extractor (also a CLI)
    auth                 local accounts, PBKDF2 passwords, roles, lockout, sealed account store
    admin_pages          sign-in, first-run setup, Audit log, Users and My account pages
    help_page            Help & glossary page
    assistant            offline help assistant (floating chat)
    ui_theme             "Emerald Forensics" theme, components and the interactive background
"""

__version__ = "2.0.0"
