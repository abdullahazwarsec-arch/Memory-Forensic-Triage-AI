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
├── evidence_integrity.py       # Hashing, tamper-evident custody ledger, manifests, sidecars
├── ui_theme.py                 # Dashboard theme and reusable UI components
├── run_app.bat                 # Double-click launcher for Windows
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── .streamlit/config.toml      # Theme, upload limit (8 GB) and toolbar settings
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
│   ├── verify_data_integrity.py / validate_input.py
│   └── create_viva_doc.py / create_commands_runbook_docx.py
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
    └── triage_audit.log             # Audit log: case sessions, custody events, verdicts
```

## Dataset
The models are trained on **CIC-MalMem2022** (`Obfuscated-MalMem2022.csv`): 58,596 memory snapshots described by 55 Volatility-derived features (processes, DLLs, handles, injected code, hidden processes, services, kernel callbacks), covering benign snapshots and 15 malware families across ransomware, spyware and trojan categories. The CSV is not committed because of its size; place it in `data/` before training.

## Setup Instructions
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
```

4. Run the dashboard — double-click `run_app.bat`, or:

```bash
streamlit run app.py
```

Then open http://localhost:8501.

5. (Optional) Extract features from a memory dump on the command line:

```bash
python memdump_extractor.py path\to\memory.raw
```

This prints the dump's SHA-256 before and after extraction and saves the feature CSV with a `.sha256` sidecar.

> The first Volatility run on a new Windows version needs internet access to download kernel symbol tables.

## How the App Works
1. **Open a case session.** Enter a case number and the analyst's name (both mandatory) plus an optional unit and notes. The opening time is recorded in local time (with UTC offset) and UTC. Nothing else is available until a case is open; closing the case records the closing time.
2. **Load evidence** — a sample profile, a Volatility CSV, or a raw memory dump (uploaded or referenced by path). The evidence is hashed on arrival and gets an evidence item ID; uploads are preserved as write-protected working copies.
3. **Analyse a snapshot.** The dashboard shows a verdict panel (malware score gauge, risk level, classification, zero-day check, integrity status) and tabs for:
   - **Overview** — recommended response steps and the top reasons for the verdict
   - **Explainability** — interactive SHAP and LIME charts, driver cards and full tables
   - **Chain of custody** — case/evidence/analyst details, all hashes, the custody ledger, manifest download and on-demand re-verification
   - **Report** — download the sealed PDF and see its hash
   - **Audit log** — recent audit entries
4. **Scan all rows** scores every snapshot in the evidence file at once.

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

Each ledger entry records the analyst and stores the hash of the previous entry, so editing any recorded entry breaks the chain and is detected. Per-case records are kept in `outputs/cases/<case>/`:
- `case.json` — sessions (analyst, opened/closed times) and evidence items
- `<evidence-id>/custody_manifest.json` — the full ledger for that evidence item

Any file can be verified independently with `certutil -hashfile <file> SHA256` (Windows) or `sha256sum <file>`.

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
- **Custody ledger is tamper-evident, not tamper-proof.** Someone with full file access could rebuild the whole chain; there is no digital signature or trusted timestamp yet.
- **No authentication.** Streamlit serves on all network interfaces by default; restrict it to `localhost` or add access control before using real evidence.
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
