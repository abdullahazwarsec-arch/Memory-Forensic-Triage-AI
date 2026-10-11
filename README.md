# MemTriage XAI — Explainable AI Memory Forensics Triage

## Project Overview
This project is a final-year university project focused on building an explainable AI-based memory forensics triage system. It detects suspicious or malicious Windows memory profiles using machine learning, explains every prediction in analyst-friendly language, and preserves a verifiable chain of custody for every piece of evidence it handles.

The system provides:
- **Raw memory dump analysis** — upload a Windows memory image (`.raw`, `.mem`, `.vmem`, `.dmp`, …) and Volatility 3 extracts the 55 memory features automatically
- **CSV analysis** — analyse Volatility-derived feature CSVs or built-in sample profiles
- **Random Forest classification** with an **Isolation Forest** zero-day anomaly check
- **Dual XAI** — SHAP (global attribution) and LIME (local decision rules) with interactive charts
- **Forensic chain of custody** — SHA-256/MD5 hashing and re-verification at every processing stage, with a tamper-evident ledger
- **Mandatory case sessions** — case number, analyst name and timestamps recorded for every action
- **Automated PDF incident reports** sealed with their own hash
- A **Streamlit dashboard** with a dark forensic-lab interface

## Problem Statement
Memory forensics is a critical field in cybersecurity, especially when malware is fileless or memory-resident. Traditional forensic workflows often rely on manual analysis, which can be slow and error-prone. This project explores whether machine learning, combined with explainable AI, can assist investigators in identifying suspicious memory behaviour more efficiently — without compromising the evidential integrity that forensic work requires.

## Project Objectives
1. Build a machine learning model that classifies memory profiles as benign or malicious.
2. Use a dual XAI framework to generate interpretable explanations for model decisions.
3. Accept both raw memory dumps and feature CSVs, converting dumps to features automatically.
4. Prove that evidence is not modified by the tool, from acquisition to the final report.
5. Record who analysed what, and when, under a case number.
6. Simulate adversarial or zero-day-like memory scenarios to evaluate model robustness.
7. Generate automated, verifiable incident reports for analyst handoff.

## Workflow

```text
 1. Case session      Analyst opens a case (case number + analyst name required; time recorded)
        │
 2. Evidence intake   Sample profile │ Volatility CSV │ raw memory dump
        │             → SHA-256 + MD5 taken on arrival (acquisition baseline)
        │
 3. Extraction        Memory dumps only: 9 Volatility 3 plugins → 55-feature CSV
        │             → dump re-hashed before and after Volatility; CSV hashed
        │
 4. Triage            Hashes re-verified → Random Forest + Isolation Forest → SHAP + LIME
        │             → the exact feature vector sent to the model is hashed and checked
        │
 5. Report            Hashes re-verified → PDF generated → PDF hash recorded (sealed)
```

If any re-computed hash does not match the acquisition hash, analysis and report generation are **blocked** and the violation is logged.

## Project Structure

```text
Memory_Forensics_Project/
├── app.py                      # Main Streamlit dashboard (case sessions, triage, XAI, reporting)
├── memdump_extractor.py        # Volatility 3 memory dump → 55-feature CSV extractor (also a CLI)
├── evidence_integrity.py       # Hashing, HMAC custody ledger, manifest verifier, model hash pinning
├── input_validation.py         # Intake checks (size, CSV structure, memory-image signatures) and feature gate
├── audit_log.py                # HMAC-chained, tamper-evident audit log handler, verifier and parser
├── auth.py                     # User accounts: PBKDF2 password hashing, roles, lockout, sealed account store
├── admin_pages.py              # Sign-in, first-run setup, Audit log, Users and My account pages
├── ui_theme.py                 # Dashboard theme and reusable UI components
├── run_app.bat                 # Double-click launcher for Windows
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── .streamlit/config.toml      # Theme, upload limit (8 GB) and toolbar settings
│
├── docs/                       # Project documentation
│   └── Memory_Forensics_Commands_And_Execution_Runbook.docx  # Every command, explained
│
├── data/                       # Forensic datasets & evaluation telemetry
│   ├── Obfuscated-MalMem2022.csv   # Primary benchmark dataset (not committed — download separately)
│   ├── apt_zero_day.csv            # Simulated zero-day memory scenario
│   ├── simulated_cobalt_strike.csv # Simulated memory beaconing dump
│   └── test_samples/               # Curated evaluation profiles for triage testing
│
├── models/                     # Trained ML models
│   ├── random_forest_model.pkl      # Binary classifier (55 memory artefacts)
│   ├── isolation_forest.pkl         # Zero-day unsupervised anomaly detection
│   └── multiclass_random_forest.pkl # Multi-class malware family model
│
├── scripts/                    # Training, evaluation & utility pipelines
│   ├── train_model.py / train_multiclass.py   # Model training
│   ├── evaluate_model.py / benchmark.py       # Evaluation, cross-validation, model comparison
│   ├── explain_model.py / test_lime.py        # SHAP / LIME explainability scripts
│   ├── generate_report.py                     # Standalone PDF report generator
│   ├── simulate_zeroday.py / generate_synthetic_threats.py
│   ├── extract_confident_samples.py / extract_real_benign.py
│   ├── verify_data_integrity.py / pin_model_hashes.py
│   ├── manage_users.py                        # Account recovery from the command line
│   └── create_viva_doc.py / create_commands_runbook_docx.py   # build the Word documents
│
├── outputs/                    # Evaluation artefacts and generated reports
│   ├── cases/                       # Per-case workspaces (generated, not committed)
│   ├── extracted/                   # Volatility extraction output (generated, not committed)
│   ├── forensic_report_*.pdf        # Sealed incident reports (+ .sha256 sidecars)
│   ├── confusion_matrix.png, roc_curve.png, shap_summary.png
│   ├── system_workflow_diagram.png, data_flow_diagram.png
│   └── model_comparison.csv
│
└── logs/
    ├── triage_audit.log             # HMAC-chained audit log: case sessions, custody events, verdicts
    └── triage_audit.log.head        # Keyed line count + last chain value (detects tail truncation)
```

## Dataset
The models are trained on **CIC-MalMem2022** (`Obfuscated-MalMem2022.csv`): 58,596 memory snapshots described by 55 Volatility-derived features (processes, DLLs, handles, injected code, hidden processes, services, kernel callbacks), covering benign snapshots and 15 malware families across ransomware, spyware and trojan categories. The CSV is not committed because of its size; place it in `data/` before training.

## Setup Instructions
For a full, explained list of every command (setup, dashboard, Volatility, hash verification, scripts, Git and troubleshooting), see [`docs/Memory_Forensics_Commands_And_Execution_Runbook.docx`](docs/Memory_Forensics_Commands_And_Execution_Runbook.docx).

1. Create and activate a virtual environment (Python 3.11 recommended):

```bash
python -m venv venv
venv\Scripts\activate            # Windows
```

2. Install dependencies (includes Volatility 3):

```bash
pip install -r requirements.txt
```

3. (Optional) Re-train and evaluate the models:

```bash
python scripts/train_model.py
python scripts/evaluate_model.py
python scripts/explain_model.py
python scripts/pin_model_hashes.py   # re-pin model hashes after any re-training, then commit models/model_hashes.json
```

4. Run the dashboard — double-click `run_app.bat`, or:

```bash
streamlit run app.py
```

Then open http://localhost:8501. On the very first start the dashboard asks you to create the **administrator account**; after that every user signs in.

5. (Optional) Extract features from a memory dump on the command line:

```bash
python memdump_extractor.py path\to\memory.raw
```

This prints the dump's SHA-256 before and after extraction and saves the feature CSV with a `.sha256` sidecar.

> The first Volatility run on a new Windows version needs internet access to download kernel symbol tables.

## How the App Works
0. **Sign in.** Every page requires an account (see [User Accounts & Access Control](#user-accounts--access-control)).
1. **Open a case session.** Enter a case number plus an optional unit and notes; the analyst is the signed-in account. The opening time is recorded in local time (with UTC offset) and UTC. Nothing else is available until a case is open; closing the case records the closing time.
2. **Load evidence** — a sample profile, a Volatility CSV, or a raw memory dump (uploaded or referenced by path). The evidence is hashed on arrival and gets an evidence item ID; uploads are preserved as write-protected working copies.
3. **Analyse a snapshot.** The dashboard shows a verdict panel (malware score gauge, risk level, classification, zero-day check, integrity status) and tabs for:
   - **Overview** — recommended response steps and the top reasons for the verdict
   - **Explainability** — interactive SHAP and LIME charts, driver cards and full tables
   - **Chain of custody** — case/evidence/analyst details, all hashes, the custody ledger, manifest download and on-demand re-verification
   - **Report** — download the sealed PDF and see its hash
   - **Audit log** — recent audit entries
4. **Scan all rows** scores every snapshot in the evidence file at once.

## User Accounts & Access Control
| Role | Pages |
|---|---|
| **Analyst** | Triage, My account |
| **Administrator** | Triage, **Audit log**, **Users**, My account |

- **First run** creates the administrator. Administrators create further accounts on the **Users** page with a temporary password; the user must choose a new one at first sign-in. Administrators can also disable/enable accounts, change roles, unlock accounts and reset passwords (an administrator cannot disable or demote themselves, and at least one active administrator always remains).
- **Passwords** are stored only as salted PBKDF2-HMAC-SHA256 hashes (600,000 iterations); at least 10 characters with letters and digits, not containing the username.
- **Lockout:** 5 consecutive failed sign-ins lock an account for 15 minutes. Sign-in errors are generic, and unknown usernames take the same time to reject, so accounts cannot be probed.
- **Sessions** end on sign-out, after 30 minutes of inactivity, or immediately when an administrator disables the account. Signing out closes any open case session.
- **Account store** `keys/users.json` (git-ignored) is sealed with an HMAC under the ledger key; a hand-edited file disables sign-in until restored.
- **Case attribution:** the analyst on case records, custody ledgers and PDF reports is the authenticated account (`Full Name (username)`), no longer a typed name.

### Audit log page
Administrators see every sign-in event read from the HMAC-chained audit log, with each entry's integrity status:
- **Sign-ins & sign-outs** — successful and failed sign-ins (with reason), lockouts, sign-outs, idle timeouts and revoked sessions, with session duration and client address; filter by user, event and date range; CSV export.
- **Account administration** — accounts created, passwords changed/reset, roles changed, accounts disabled/enabled/unlocked, and who did it.
- **All audit events** — the complete log (case sessions, custody events, verdicts, reports, validation, model checks) with category/level filters and search.

Each user can see their own recent sign-in activity on **My account**. Closing the browser tab without signing out is not recorded as a sign-out; the session simply expires.

Account recovery (e.g. the only administrator is locked out) — every action is audited as `cli:<OS user>`:

```bash
python scripts/manage_users.py list
python scripts/manage_users.py reset-password <username>
python scripts/manage_users.py unlock <username>
python scripts/manage_users.py create <username> "<Full Name>" --role admin
```

## Chain of Custody & Evidence Integrity
Every artefact is fingerprinted with SHA-256 and MD5 and re-verified at each stage:

| Stage | What is verified |
|---|---|
| Acquisition | Hash of the exact bytes received (the baseline) |
| Working copy | Write-protected copy of uploaded evidence matches the baseline |
| Pre-/Post-extraction | Memory dump unchanged by Volatility |
| Derived data | Feature CSV hashed and linked to the dump's hash |
| Data load | CSV re-hashed when parsed |
| Pre-analysis | Evidence and CSV re-hashed before inference |
| Analysis input | The exact feature vector sent to the model matches the verified file |
| Pre-report | Everything re-hashed before the PDF is built |
| Report | PDF hash recorded in the ledger, audit log and a `.sha256` sidecar |

Each ledger entry records the analyst and is chained to the previous entry by an **HMAC-SHA256** link keyed with a secret ledger key, so editing any recorded entry breaks the chain, and the chain cannot be rebuilt without the key. The key is created on first run at `keys/ledger_hmac.key` (git-ignored, write-protected) or can be supplied as 64+ hex characters in the `FORENSICS_LEDGER_KEY` environment variable. Back it up securely — manifests sealed with a lost key can no longer be verified. Per-case records are kept in `outputs/cases/<case>/`:
- `case.json` — sessions (analyst, opened/closed times) and evidence items
- `<evidence-id>/custody_manifest.json` — the full ledger for that evidence item

Any file can be verified independently with `certutil -hashfile <file> SHA256` (Windows) or `sha256sum <file>`. A custody manifest is re-verified (every HMAC link recomputed) with:

```bash
python evidence_integrity.py verify outputs/cases/<case>/<evidence-id>/custody_manifest.json
```

### Model integrity
Models are pickle files, and unpickling a tampered file can execute code. The dashboard therefore reads each model once, checks its SHA-256 against `models/model_hashes.json`, and only then unpickles those verified bytes. An unpinned or modified classifier stops the dashboard; an unverified Isolation Forest is disabled with a warning. Both outcomes are written to the audit log.

### Input validation
Evidence is checked before a case record is created and again before it reaches the models:

| Gate | Check | On failure |
|------|-------|------------|
| Feature CSV upload | ≤ 50 MB, UTF-8 text with no binary data, parsable CSV, header contains model features | Rejected, logged as `INTAKE REJECTED` |
| Memory image (upload or path) | Supported extension, ≥ 64 MB, file signature (`.dmp` must be `PAGEDU64`/`PAGEDUMP`, `.lime` must be `EMiL`; archives, executables, documents and E01 containers are refused) | Rejected, logged |
| Working copy | Free disk space ≥ image size + 1 GB | Rejected — analyse in place via the path option |
| Feature gate | All 55 model features present, numeric, finite and non-negative | Missing / empty / non-numeric values: analyst must acknowledge before analysis. More than 20% of features unusable, or any infinite or negative value: **analysis blocked** |

Every result is recorded in the custody ledger (`Input Validation` stage) and the audit log; an acknowledgement records the analyst's name. The result also appears in the PDF report.

### Tamper-evident audit log
Each line of `logs/triage_audit.log` ends with `CHAIN=<HMAC-SHA256>` over the previous chain value and the line, keyed with the ledger key. Editing, inserting, deleting or reordering a line breaks the chain. The first chained line (`AUDIT LOG CHAIN GENESIS`) stores the size and SHA-256 of all earlier unchained history, and a keyed `.head` file detects lines removed from the end. Line breaks in logged values are escaped, so crafted input cannot forge log lines. The dashboard sidebar shows the chain status; verify manually with:

```bash
python audit_log.py verify
```

## Memory Dump Feature Extraction
`memdump_extractor.py` runs `windows.info` followed by 9 Volatility 3 plugins (`pslist`, `dlllist`, `handles`, `ldrmodules`, `malfind`, `psxview`, `modules`, `svcscan`, `callbacks`) and converts their output into the 55 CIC-MalMem2022 features. Volatility 3 lacks some checks used to build the original dataset, so a few features are approximations:
- `psxview` session / desktop-thread views are derived from other views
- service records are de-duplicated before counting
- `malfind.protection` is the sum of VAD protection codes

Only Windows memory images are supported.

## Evaluation and Results
The evaluation pipeline generates a confusion matrix, ROC curve, classification report, cross-validation metrics and a comparative model performance table (`outputs/`).

## Explainability and XAI Framework
- **SHAP** (TreeExplainer) quantifies how much each memory feature pushed this verdict toward malware or benign.
- **LIME** fits local surrogate rules around the analysed snapshot as an independent check.

Both are shown as interactive diverging bar charts (red = toward malware, blue = toward benign) with plain-English descriptions of each feature, and both are included in the PDF report.

## Known Limitations
These are findings from testing the current models. They are documented so results are interpreted correctly.
- **Optimistic accuracy.** The 100% test accuracy comes from a random train/test split. Each malware sample has ~10 near-identical snapshots and the dataset contains 534 duplicate rows, so near-copies appear in both train and test.
- **Shortcut learning.** Only 11 service/module/callback count features reach 99.99% accuracy, and benign `svcscan.nservices` only ranges from 388 to 395, because the benign snapshots come from essentially one machine configuration. The model largely learns "differs from that benign machine" rather than malware behaviour. As a result, some benign-labelled sample profiles score as high risk, and real dumps from other Windows versions can be misjudged.
- **Explanations reflect this bias.** SHAP/LIME correctly show that service and driver counts drive the verdict; they explain the model, not ground truth.
- **Custody ledger is keyed, not signed.** Rebuilding the chain requires the ledger key, but anyone who can read `keys/ledger_hmac.key` could still forge a ledger; there is no asymmetric signature or trusted timestamp yet. Model pins protect against replaced model files, not against someone who can also edit `model_hashes.json` and the code.
- **Audit log head can be rolled back.** Someone with file access who saved an older log and `.head` pair could restore both together; only an external copy of the head (e.g. in the case notes) rules this out.
- **Local accounts only.** Sign-in uses local accounts without multi-factor authentication and the dashboard is served over plain HTTP on `localhost`. Anyone with file access to `keys/` can reset accounts with `scripts/manage_users.py`; put TLS and SSO/MFA in front before exposing it beyond the examiner's machine.
- Volatility symbol downloads require internet on first use; uploaded dumps are held in memory (use the path option for large dumps); Windows images only.

## Future Work
- Re-train with duplicates removed and a split grouped by sample; add benign dumps from many machines and OS versions; normalise environment-specific count features.
- Validate on real external memory dumps; calibrate probabilities; warn when an input falls outside the training distribution.
- Show per-process Volatility findings (injected regions, hidden processes) with PIDs as evidence alongside the verdict.
- Verify against the acquisition tool's hash at intake; sign custody manifests and add trusted timestamps; add user authentication.
- Measure SHAP/LIME agreement and LIME stability; add base-value breakdowns and counterfactual explanations; integrate the multiclass family model.
- Record tool and model versions (including the model file hash) in each report for reproducibility.

## Notes
This project is a practical final-year demonstration of explainable AI for memory forensics. It is a research prototype, not a production forensic tool; automated verdicts must be reviewed by a qualified analyst.
