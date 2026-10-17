from pathlib import Path
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "outputs"
DOCX_PATH = BASE_DIR / "docs" / "Memory_Forensics_AI_Triage_Viva_Defense_Guide.docx"

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)

def add_callout(doc, title, text, bg_hex="F2F4F8", border_hex="1F3864"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=120, bottom=120, left=180, right=180)
    
    # Left border styling
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:left w:val="single" w:sz="24" w:space="0" w:color="{border_hex}"/>'
        f'<w:top w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'<w:bottom w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(4)
    run_t = p.add_run(f"📌 {title}\n")
    run_t.bold = True
    run_t.font.name = "Calibri"
    run_t.font.size = Pt(11)
    run_t.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
    
    run_b = p.add_run(text)
    run_b.font.name = "Calibri"
    run_b.font.size = Pt(10.5)
    run_b.font.italic = True
    run_b.font.color.rgb = RGBColor(0x33, 0x33, 0x33)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def format_table(table, col_widths, col_names, data_rows):
    # Header
    hdr_cells = table.rows[0].cells
    for i, name in enumerate(col_names):
        hdr_cells[i].text = name
        set_cell_background(hdr_cells[i], "1F3864")
        set_cell_margins(hdr_cells[i], top=100, bottom=100, left=140, right=140)
        p = hdr_cells[i].paragraphs[0]
        p.runs[0].font.bold = True
        p.runs[0].font.name = "Calibri"
        p.runs[0].font.size = Pt(10)
        p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        
    for row_idx, row_data in enumerate(data_rows):
        row = table.add_row()
        bg_color = "F9FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for col_idx, text in enumerate(row_data):
            cell = row.cells[col_idx]
            cell.text = str(text)
            set_cell_background(cell, bg_color)
            set_cell_margins(cell, top=80, bottom=80, left=140, right=140)
            p = cell.paragraphs[0]
            if len(p.runs) > 0:
                p.runs[0].font.name = "Calibri"
                p.runs[0].font.size = Pt(9.5)
                p.runs[0].font.color.rgb = RGBColor(0x22, 0x22, 0x22)
                
    for row in table.rows:
        for idx, width in enumerate(col_widths):
            row.cells[idx].width = width

def build_document():
    doc = docx.Document()
    
    # Page setup - 1 inch margins
    sections = doc.sections
    for s in sections:
        s.top_margin = Inches(1)
        s.bottom_margin = Inches(1)
        s.left_margin = Inches(1)
        s.right_margin = Inches(1)
        
    # Styles setup
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Calibri'
    style_normal.font.size = Pt(11)
    style_normal.font.color.rgb = RGBColor(0x2A, 0x2A, 0x2A)
    
    # Document Title Block
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(4)
    title_run = title_p.add_run("MEMORY FORENSICS AI TRIAGE DASHBOARD")
    title_run.font.name = "Calibri"
    title_run.font.size = Pt(24)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
    
    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(16)
    sub_run = sub_p.add_run("Comprehensive Project Technical Guide & Viva Defense Preparation Dossier\nExplainable AI (XAI) Memory Forensics Framework with SHAP & LIME")
    sub_run.font.name = "Calibri"
    sub_run.font.size = Pt(13)
    sub_run.font.italic = True
    sub_run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    
    # Metadata Box
    meta_table = doc.add_table(rows=1, cols=4)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_cells = meta_table.rows[0].cells
    meta_items = [
        ("Project Type", "Final Year Research / Defense"),
        ("Core Algorithm", "Random Forest + Isolation Forest"),
        ("Explainability", "Dual XAI (SHAP + LIME)"),
        ("Evaluation Metric", "99.93% grouped-CV accuracy (honest split) + shortcut analysis")
    ]
    for idx, (label, val) in enumerate(meta_items):
        cell = meta_cells[idx]
        set_cell_background(cell, "EBF1F5")
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r1 = p.add_run(f"{label}\n")
        r1.font.bold = True
        r1.font.size = Pt(9)
        r1.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
        r2 = p.add_run(val)
        r2.font.size = Pt(9.5)
        r2.font.color.rgb = RGBColor(0x11, 0x11, 0x11)
        
    doc.add_paragraph().paragraph_format.space_after = Pt(12)
    
    # ── SECTION 1: 60-SECOND VIVA ELEVATOR PITCH ─────────────────────────────
    h1 = doc.add_heading("1. The 60-Second Viva Elevator Pitch (How to Introduce Your Project)", level=1)
    h1.paragraph_format.space_before = Pt(12)
    h1.paragraph_format.space_after = Pt(6)
    
    add_callout(
        doc,
        "What to Say to Your Professor / Examiner Word-for-Word:",
        "\"Sir, modern malware—such as fileless ransomware, stealth rootkits, and Cobalt Strike beacons—increasingly avoids the hard drive completely and operates solely in volatile memory (RAM). Traditional forensic examination of 16GB–64GB RAM dumps with manual Volatility plugins takes hours and requires deep reverse-engineering expertise.\n\n"
        "In this project, I developed an Autonomous Explainable AI Memory Forensics Triage System. The system ingests volatile memory profiles containing 55 kernel and process telemetry artifacts. Using a tuned Random Forest classifier, it categorizes memory profiles into Benign or Malicious. I evaluated it honestly: duplicates removed, folds grouped by malware sample so snapshots of one sample never appear in both training and testing, and whole malware families held out. It scores 99.93% under grouping - but I also show that one rule on the number of Windows services scores 99.66%, because the dataset's clean data comes from one machine. So I present the result as strong on this dataset, with a clearly stated limitation for real-world use. For memory dumps the system also points to the specific suspicious processes, and it gives a likely malware type as a hint.\n\n"
        "Crucially, in cyber forensics, an AI decision is useless without proof. To solve the 'AI Black Box' dilemma, I implemented a Dual Explainable AI (XAI) Framework combining SHAP (global cooperative game theory) and LIME (local surrogate decision rules), corroborated by a Plain-English Forensic Translation Engine. The entire system is deployed via an interactive Streamlit dashboard featuring SHA-256 chain-of-custody audit logging and automated PDF incident dossier generation for incident response teams.\""
    )

    # ── SECTION 2: SYSTEM ARCHITECTURE & HIGH-LEVEL OVERVIEW ─────────────────
    h1 = doc.add_heading("2. High-Level Architecture & End-to-End Workflow", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    doc.add_paragraph(
        "The project operates as an end-to-end autonomous triage pipeline that transforms raw volatile memory dump telemetry into actionable, legally admissible forensic intelligence. The complete system follows a 7-stage workflow:"
    )
    
    stages = [
        ("Stage 1: Evidence Ingestion & Pre-flight Gating", "The analyst either uploads a Volatility-extracted memory profile (CSV) or selects a pre-packaged live forensic baseline. The system validates schema structure, aligns all 55 required feature headers, and runs the input_validation.py feature gate: missing, empty or non-numeric values require analyst acknowledgement, and infinite/negative values or more than 20% unusable features block the analysis."),
        ("Stage 2: Dual Ensemble Inference Engine", "The memory profile is passed through two complementary machine learning engines: (1) Random Forest Classifier (150 trees) predicting binary infection probability, and (2) Isolation Forest Anomaly Detector checking whether the profile deviates from known behavioral clusters (Zero-Day threat detector)."),
        ("Stage 3: Risk Classification & Triage Tiering", "Based on probability thresholds, samples are placed into operational incident tiers: NORMAL (< 40% probability), SUSPICIOUS (40% - 75%), or HIGH RISK (>= 75%)."),
        ("Stage 4: Cryptographic Chain of Custody", "Every triage execution computes a SHA-256 hash across filename, row index, and high-resolution timestamp (Evidence ID), appending an immutable entry to logs/triage_audit.log."),
        ("Stage 5: Dual XAI Explainability (SHAP + LIME)", "SHAP TreeExplainer computes mathematical Shapley attribution values across all 55 features. Concurrently, LIME generates local perturbation-based surrogate rules to provide independent local corroboration."),
        ("Stage 6: Plain-English Forensic Feature Translation", "Raw kernel metric identifiers (e.g., malfind.ninjections, psxview.not_in_eprocess) are translated through FEATURE_MEANINGS into human-readable descriptions, danger context, and impact explanations for non-technical stakeholders."),
        ("Stage 7: Autonomous Incident Reporting & Archival", "A ReportLab PDF generation engine automatically compiles an official, executive Forensic Incident Dossier containing the triage verdict, chain-of-custody hash, top XAI decision drivers, and recommended response playbooks.")
    ]
    
    for title, desc in stages:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.25)
        p.paragraph_format.space_after = Pt(4)
        r_t = p.add_run(f"• {title}: ")
        r_t.bold = True
        r_t.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
        p.add_run(desc)

    # ── SECTION 3: TOOLS & TECHNOLOGIES USED ──────────────────────────────────
    h1 = doc.add_heading("3. Tools, Libraries & Technology Stack", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    tools_data = [
        ("Python 3.11", "Primary Programming Language", "Core language used for model building, data processing, backend scripting, and UI integration."),
        ("Streamlit", "Web Dashboard & Interactive UI", "Provides the reactive, dark-themed cyber forensic interface (app.py) for uploading files, interactive charts, and PDF download buttons."),
        ("Scikit-Learn", "Machine Learning Core Engine", "Implements RandomForestClassifier, IsolationForest, LogisticRegression, GradientBoosting, StratifiedKFold, and ROC/AUC metrics."),
        ("SHAP (Shapley)", "Global Explainable AI (XAI)", "Calculates exact game-theoretic Shapley values using TreeExplainer to determine which memory artifacts pushed the verdict toward Malware or Benign."),
        ("LIME", "Local Explainable AI (XAI)", "LimeTabularExplainer generates human-readable local decision thresholds (e.g. 'handles.nhandles > 8500') for instance-level validation."),
        ("ReportLab", "Forensic PDF Compilation Engine", "Dynamically generates official, downloadable legal/incident response PDF reports complete with tables and incident response playbooks."),
        ("Pandas & NumPy", "Data Transformation & Arrays", "Data loading, feature matrix cleaning, label isolation, zero-padding, and tabular data structures."),
        ("Matplotlib", "Forensic Data Visualization", "Renders ROC performance curves, confusion matrices, and SHAP/LIME waterfall impact horizontal bar charts."),
        ("Joblib", "Model Serialization & Archival", "Serializes trained AI brains into .pkl files (random_forest_model.pkl, multiclass_random_forest.pkl, isolation_forest.pkl)."),
        ("Volatility Framework", "Forensic Artifact Reference", "The underlying digital forensics domain standard from which the 55 memory artifacts (malfind, pslist, handles, dlllist, etc.) are extracted.")
    ]
    
    table_tools = doc.add_table(rows=1, cols=3)
    table_tools.alignment = WD_TABLE_ALIGNMENT.CENTER
    format_table(
        table_tools,
        [Inches(1.5), Inches(2.0), Inches(3.0)],
        ["Tool / Library", "Project Role", "Technical Implementation Context"],
        tools_data
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # ── SECTION 4: DATASET & PREPROCESSING PIPELINE ───────────────────────────
    h1 = doc.add_heading("4. How Data is Processed (Data Pipeline & Feature Engineering)", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    doc.add_paragraph(
        "The project is built upon the Canadian Institute for Cybersecurity (CIC) benchmark dataset: Obfuscated-MalMem2022.csv. This dataset was specifically created to evaluate memory forensics systems against sophisticated obfuscation techniques."
    )
    
    doc.add_heading("Dataset Breakdown & Composition:", level=2)
    p = doc.add_paragraph()
    p.add_run("• Total Samples: ").bold = True
    p.add_run("58,596 memory dump instances balanced between benign software and active malware.\n")
    p.add_run("• Malicious Families: ").bold = True
    p.add_run("Spyware (180solutions, Coolwebsearch, Gator, Transponder, TIBS), Ransomware (Conti, Maze, Poca, WannaCry), and Trojans (Emotet, Zeus, Danabot, Trickbot).\n")
    p.add_run("• Volatile Memory Dimensions: ").bold = True
    p.add_run("55 continuous and discrete features extracted from Windows memory dumps using Volatility plugins.")

    doc.add_heading("The 55 Memory Feature Categories:", level=2)
    cat_data = [
        ("malfind (Memory Injections)", "malfind.ninjections, malfind.commitCharge, malfind.protection", "Identifies hidden code injected into memory without backing files on disk (PAGE_EXECUTE_READWRITE permissions). Hallmarks of fileless malware and Cobalt Strike beacons."),
        ("pslist & psxview (Processes)", "pslist.nproc, pslist.avg_threads, psxview.not_in_eprocess", "Cross-examines the active EPROCESS linked lists against low-level scheduler structures to identify hidden processes unlinked via Direct Kernel Object Manipulation (DKOM)."),
        ("handles (System Resources)", "handles.nhandles, handles.avg_handles_per_proc, handles.nfile, handles.nmutant", "Tracks open handles to files, mutexes, and registry keys. Dramatic spikes indicate ransomware sweeping file directories or trojans enforcing single-infection mutexes."),
        ("svcscan (Windows Services)", "svcscan.nservices, svcscan.shared_process_services, svcscan.kernel_drivers", "Monitors Windows service database modifications, rogue driver installations, and services masquerading under svchost.exe pools for persistence."),
        ("ldrmodules & dlllist (DLLs)", "dlllist.ndlls, ldrmodules.not_in_load, ldrmodules.not_in_init", "Tracks dynamic-link libraries loaded into process spaces. Flags reflective DLL injection where malware runs without completing standard Windows loader initialization."),
        ("callbacks (Kernel Hooks)", "callbacks.ncallbacks, callbacks.nanonymous", "Monitors kernel event notification callbacks registered by drivers. Anonymous callbacks indicate malicious rootkits executing in ring-0 kernel memory.")
    ]
    table_cats = doc.add_table(rows=1, cols=3)
    table_cats.alignment = WD_TABLE_ALIGNMENT.CENTER
    format_table(
        table_cats,
        [Inches(1.8), Inches(2.2), Inches(2.5)],
        ["Feature Family", "Key Volatility Metrics", "Forensic Significance & Threat Detection Value"],
        cat_data
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    doc.add_heading("Data Cleaning & Leakage Prevention:", level=2)
    doc.add_paragraph(
        "1. Label Isolation: In the raw CSV, 'Class' contains 'Benign'/'Malware' and 'Category' contains family names (e.g. 'Ransomware-Conti'). As proven in verify_data_integrity.py, the pipeline strictly separates the target vector (y) and drops all categorical strings from the feature matrix (X) to prevent target leakage.\n"
        "2. Binary Encoding: The 'Class' column is mapped to binary integer format (0 = Benign, 1 = Malware).\n"
        "3. Duplicates and grouping: train_models.py removes 569 duplicate rows. Each malware row names its sample (e.g. Trojan-Zeus-<hash>-4.raw is snapshot 4 of one sample), so cross-validation folds are grouped by sample (StratifiedGroupKFold) - snapshots of one sample never sit in both training and testing. Benign rows carry no sample id, so the benign side remains a random split.\n"
        "4. Malware type: the category prefix gives Ransomware, Spyware or Trojan; the type model is trained on malware rows only, because the binary model already decides benign vs malware."
    )

    # ── SECTION 5: HOW THE MODELS ARE TRAINED ─────────────────────────────────
    h1 = doc.add_heading("5. How the AI Models are Trained & Evaluated", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    doc.add_paragraph(
        "The project deploys three models: a binary classifier (the verdict), an unsupervised anomaly detector (zero-day check) and a malware-type model (a hint shown when the verdict is not clean). For memory dumps, rule-based per-process checks on the Volatility output (hidden processes, injected code, hidden DLLs, wrong parents, look-alike names) point to the specific processes behind the verdict."
    )
    
    model_data = [
        ("Random Forest (Binary)", "150 Estimators, max_depth=12, min_samples_split=10, min_samples_leaf=4, max_features='sqrt'", "Primary triage classifier determining if a memory profile is Benign (0) or Malicious (1).", "Grouped 5-fold: 99.93% accuracy, 99.89% recall\nUnseen families: 97.5-100% recall\nOne-rule baseline: 99.66%"),
        ("Isolation Forest (Unsupervised)", "n_estimators=100, contamination=0.01, max_samples='auto'", "Trained purely on normal/baseline profiles to identify out-of-distribution mathematical outliers (Zero-Day detector).", "Flags anomalous records with is_anomaly=True (prediction == -1)"),
        ("Malware-Type Random Forest", "150 Estimators, max_depth=15, min_samples_leaf=4, trained on malware rows only", "Shown as a hint when the verdict is not clean: likely Ransomware, Spyware or Trojan.", "Grouped 5-fold: 67.6% accuracy (chance 33%)\nRandom split: 71.4%"),
        ("Logistic Regression (Baseline)", "max_iter=2000, StandardScaler pipeline", "Used as a linear baseline in evaluate_model.py to prove superiority of non-linear tree ensembles.", "Accuracy: 99.87%\nROC-AUC: 0.9999")
    ]
    table_models = doc.add_table(rows=1, cols=4)
    table_models.alignment = WD_TABLE_ALIGNMENT.CENTER
    format_table(
        table_models,
        [Inches(1.5), Inches(2.0), Inches(1.8), Inches(1.5)],
        ["Model Architecture", "Key Hyperparameters", "Operational Purpose", "Validated Performance"],
        model_data
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # ── SECTION 6: SCRIPT DIRECTORY GUIDE ─────────────────────────────────────
    h1 = doc.add_heading("6. Complete Script Guide (What Every File in scripts/ Does)", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    scripts_info = [
        ("training/train_models.py", "Honest Training & Evaluation Pipeline", "Removes 569 duplicate rows; evaluates with random vs sample-grouped 5-fold CV, leave-one-family-out and a one-rule shortcut baseline; trains the binary Random Forest, the benign-only Isolation Forest and the malware-type model; writes models/model_card.json and docs/results/honest_evaluation.md; re-pins the model hashes."),
        ("training/train_model.py, train_multiclass.py", "Superseded (kept for reference)", "The original random-split scripts. They now stop immediately and point to train_models.py."),
        ("evaluation/evaluate_model.py", "Academic Model Evaluation & Visualization", "Runs Stratified 3-Fold Cross-Validation, compares Random Forest against Logistic Regression, exports model_comparison.csv, and generates visual artifacts: outputs/confusion_matrix.png and outputs/roc_curve.png."),
        ("evaluation/benchmark.py", "Comparative Algorithm Benchmark", "Executes 5-fold cross-validation benchmarking across Random Forest, Gradient Boosting (GBDT), and Logistic Regression to academically justify model selection."),
        ("evaluation/explain_model.py", "SHAP Global Explainability Script", "Initializes a shap.TreeExplainer on the saved model and generates outputs/shap_summary.png, graphing the top global features driving malware predictions across the dataset."),
        ("evaluation/lime_example.py", "LIME Local Attribution Validation", "Initializes LimeTabularExplainer on memory features, takes a test malware instance, and extracts local linear surrogate rules (feature conditions and weights)."),
        ("evaluation/verify_data_integrity.py", "Data Leakage & Integrity Auditor", "Audits dataset rows, verifies 0 duplicate entries, checks for target label leakage in features, and confirms all 55 features are clean numerical metrics."),
        ("admin/pin_model_hashes.py", "Model Integrity Pinning Utility", "Records the SHA-256 of every trained model in models/model_hashes.json. The dashboard verifies each model against these pins before unpickling it and refuses modified or unpinned models."),
        ("data/simulate_zeroday.py", "Adversarial Zero-Day Simulator", "Samples a heavily infected memory profile, mutates key injection and process parameters beyond training distribution, strips labels, and outputs data/apt_zero_day.csv."),
        ("data/generate_synthetic_threats.py", "Targeted Threat Profile Generator", "Creates realistic threat scenario profiles in data/test_samples/:\n• fresh_stealth_rootkit.csv (DKOM)\n• fresh_aggressive_ransomware.csv (Handles)\n• fresh_fileless_miner.csv (Injections)"),
        ("data/extract_real_benign.py", "Authentic Clean Baseline Extractor", "Extracts unlabelled, genuine benign system memory profiles from the primary dataset and exports real_benign_sample.csv for live dashboard demonstrations."),
        ("data/extract_confident_samples.py", "High-Confidence Sample Extractor", "Extracts verified 0% risk benign and 100% risk malware samples (guaranteed_benign.csv and guaranteed_malware.csv) for repeatable evaluation."),
        ("reports/generate_report.py", "Standalone PDF Report Generator", "ReportLab script that programmatically compiles a forensic triage PDF brief including executive tables, indicators, and incident response playbooks.")
    ]
    
    table_scripts = doc.add_table(rows=1, cols=3)
    table_scripts.alignment = WD_TABLE_ALIGNMENT.CENTER
    format_table(
        table_scripts,
        [Inches(1.8), Inches(1.8), Inches(2.9)],
        ["Script Filename", "Pipeline Category", "Detailed Functional Description"],
        scripts_info
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # ── SECTION 7: DASHBOARD DEEP-DIVE (app.py) ───────────────────────────────
    h1 = doc.add_heading("7. Inside the Web Application (app.py + hazmem/)", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "app.py is the Streamlit dashboard (triage workflow, models, SHAP/LIME, PDF report and the Cases page). "
        "The supporting modules live in the hazmem/ package. Here is what each part does:"
    )

    app_sections = [
        ("Accounts & sign-in (hazmem/auth.py, admin_pages.py)", "Local accounts with PBKDF2-SHA256 password hashes, Administrator and Analyst roles, a 5-attempt lockout, 30-minute idle timeout and forced password change for new accounts. The account store is sealed with an HMAC so it cannot be edited by hand."),
        ("Case sessions & provenance (app.py)", "Every analysis runs inside a case opened by the signed-in analyst, recording who the findings are prepared for (recipient, purpose, reference) and, for each evidence item, where it came from (device, custodian, location, collector, time, tool) plus the optional hash reported by the acquisition tool."),
        ("Evidence integrity (hazmem/evidence_integrity.py)", "SHA-256/MD5 hashing at every stage and an HMAC-keyed chain-of-custody ledger: each event is linked to the previous one with a secret key, so the ledger cannot be edited and re-chained. Model files are verified against pinned hashes before they are loaded."),
        ("Input validation (hazmem/input_validation.py)", "Rejects oversized, binary or unrelated uploads and checks memory-image file signatures. The feature gate blocks infinite/negative values or >20% missing features and requires analyst acknowledgement for smaller gaps."),
        ("Memory dump extraction (hazmem/memdump_extractor.py)", "Runs windows.info plus 9 Volatility 3 plugins and builds the 55 CIC-MalMem2022 features, hashing the image before and after to prove it was not modified."),
        ("Models & explainability (app.py)", "Random Forest probability and risk tier, Isolation Forest zero-day check, SHAP (TreeExplainer) global drivers and LIME local rules, shown as diverging charts and plain-English driver cards."),
        ("Sealed PDF report (app.py)", "ReportLab dossier with provenance, verdict, SHAP/LIME tables, response actions and the full custody ledger; its SHA-256 is recorded in the ledger, the audit log and a .sha256 sidecar."),
        ("Tamper-evident audit log (hazmem/audit_log.py)", "Every sign-in, account change, case event and verdict is written as an HMAC-chained line under a file lock; edits, deletions, truncation and duplicates are detected and shown on the administrator's Audit log page."),
        ("Usability (help_page.py, assistant.py, ui_theme.py, knowledge.py)", "A simple view by default (plain-English result, everyday next steps) with a Show technical details switch for hashes, ledger and SHAP/LIME; Cases page, Help page with glossary and FAQ, an offline help assistant, the Royal Purple theme with Light/Dark/Auto modes and an interactive background."),
    ]
    for title, desc in app_sections:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.2)
        p.paragraph_format.space_after = Pt(3)
        r_t = p.add_run(f"• {title}: ")
        r_t.bold = True
        p.add_run(desc)

    # ── SECTION 8: EXPLAINABLE AI (XAI) DEEP-DIVE ─────────────────────────────
    h1 = doc.add_heading("8. The Explainable AI (XAI) Framework: SHAP vs. LIME", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    doc.add_paragraph(
        "One of the biggest strengths of this project is the Dual XAI Framework. In forensic science, evidence must be explainable in a court of law. An analyst cannot simply say 'The AI said it was malware.'"
    )
    
    xai_comp = [
        ("Foundational Theory", "Cooperative Game Theory (Lloyd Shapley, 1953). Treats features as players in a game cooperating to achieve a prediction.", "Local Perturbation Surrogate Modeling (Ribeiro et al., 2016). Treats the model as a black box and probes it locally."),
        ("Explainability Scope", "Global & Instance-Level: Guarantees consistency across all 55 features and all possible subsets.", "Local Instance-Level: Explains the decision boundary strictly in the immediate neighborhood of the single evaluated memory profile."),
        ("Output Representation", "Exact additive contribution values (SHAP values) indicating the percentage push toward Malware or Benign.", "Interpretable threshold rules (e.g., 'handles.avg_handles_per_proc > 9800.00: +0.45 toward Malware')."),
        ("Role in This Project", "Identifies the core mathematical decision drivers across the Random Forest decision tree ensemble.", "Provides independent, human-readable local rule corroboration to validate the SHAP findings.")
    ]
    table_xai = doc.add_table(rows=1, cols=3)
    table_xai.alignment = WD_TABLE_ALIGNMENT.CENTER
    format_table(
        table_xai,
        [Inches(1.8), Inches(2.4), Inches(2.4)],
        ["Comparison Dimension", "SHAP (TreeExplainer)", "LIME (LimeTabularExplainer)"],
        xai_comp
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # ── SECTION 9: TOP VIVA QUESTIONS & WINNING MODEL ANSWERS ─────────────────
    h1 = doc.add_heading("9. Examiner / Professor Viva Questions & Model Answers", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    viva_qa = [
        (
            "Q1: Why did you use Random Forest instead of Deep Learning (like CNNs or LSTMs)?",
            "\"Sir, memory forensics telemetry is tabular, structured data with 55 discrete numerical features. In academic machine learning literature (such as the extensive benchmark studies by Grinsztajn et al. and Shwartz-Ziv & Armon), tree-based ensemble architectures like Random Forest and Gradient Boosting consistently outperform deep neural networks on tabular datasets.\n\n"
            "Furthermore, Random Forest offers three critical forensic advantages: (1) it does not easily overfit on correlated tabular data, (2) it allows exact, mathematically rigorous TreeSHAP computation without requiring differentiable approximations, and (3) its inference takes under 50 milliseconds, making it ideal for rapid incident triage.\""
        ),
        (
            "Q2: What is 'Data Leakage' and how did you mathematically ensure it did not occur?",
            "\"Data leakage occurs when information from outside the training dataset is used to create the model, artificially inflating test performance. In the MalMem2022 dataset, the raw CSV contained columns like 'Category' (which explicitly spelled out the malware family, e.g., 'Trojan-Emotet') and 'Class' ('Benign' vs 'Malware').\n\n"
            "In our data pipeline (audited in scripts/evaluation/verify_data_integrity.py), we strictly isolated 'Class' as the prediction label y and completely dropped 'Category' before training. The model was trained purely on the 55 independent volatile memory telemetry features (X). In addition, train-test splitting was performed using stratified sampling prior to any model fitting, ensuring no test data was seen during training.\""
        ),
        (
            "Q3: Your Random Forest model achieves near 100% accuracy. Is it overfitting?",
            "\"Sir, I checked this carefully, and the honest answer has two parts.\n\n"
            "1. Not leakage: each malware sample has about 10 snapshots, so a random split puts near-copies in training and testing. I removed 569 duplicates and grouped the folds by sample - accuracy only moved from 99.98% to 99.93%. Holding out each of the 15 families completely, the model still detected 97.5-100% of the unseen family.\n"
            "2. But a shortcut: a single rule, svcscan.nservices <= 390.5, scores 99.66% on its own, because every clean snapshot comes from one machine with 388-395 services. Removing all service features still leaves 99.93%, so the machine fingerprint is spread across many counts. The dataset is too easy to prove real-world accuracy: a clean dump from a different Windows machine may be flagged. The dashboard states this under How reliable is this result?, and the fix is benign dumps from many machines.\n"
            "3. What the evidence supports: strong separation on this benchmark, explanations (SHAP/LIME) that reveal which counts the model relies on, and per-process checks that give the analyst concrete leads.\""
        ),
        (
            "Q4: How does your system handle Zero-Day or novel malware attacks?",
            "\"Traditional antivirus software relies on signature databases; when an attacker modifies a single byte, the hash changes and static detection fails. Our system addresses zero-days on two levels:\n\n"
            "1. Behavioral Memory Artifacts: Even if a malware strain is completely new, its operational behavior in RAM cannot be concealed. To run code filelessly, it must allocate RWX memory (malfind.protection); to evade Task Manager, it must unlink its EPROCESS block (psxview.not_in_eprocess). The Random Forest detects these fundamental malicious patterns.\n"
            "2. Unsupervised Isolation Forest: In addition to the supervised classifier, we integrated an unsupervised Isolation Forest model trained on baseline distributions. If a novel memory dump deviates mathematically from known clusters, the system triggers a 'Zero-Day / Anomaly Alert' recommending immediate memory carving.\""
        ),
        (
            "Q5: What is the purpose of the Chain-of-Custody feature in your system?",
            "\"In digital forensics and incident response, evidence must be legally defensible. If an investigator cannot prove that evidence was untampered with, the entire forensic report is inadmissible in court.\n\n"
            "To solve this, our system automatically computes a cryptographic SHA-256 hash combining the source filename, row index, and high-resolution timestamp for every triage execution. This unique Evidence Identifier is stamped onto the dashboard, embedded in the generated PDF dossier, and immutably recorded in logs/triage_audit.log, establishing an unbroken chain of custody.\""
        ),
        (
            "Q6: What are the current limitations of the project and how can it be improved?",
            "\"Sir, there are three primary areas for future extension:\n\n"
            "1. End-to-End Raw RAM Ingestion: Currently, the dashboard ingests pre-extracted Volatility CSV telemetry. A logical next step is embedding the Volatility 3 Python API directly into the backend so analysts can drop a raw 16GB .raw or .dmp memory file and have features extracted automatically.\n"
            "2. Live Endpoint Agent: Packaging the triage engine as a lightweight endpoint detection agent that extracts memory metrics on live Windows hosts periodically.\n"
            "3. Adversarial Robustness Testing: Further evaluating how the model performs against sophisticated anti-forensic techniques designed to poison memory telemetry counters.\""
        )
    ]
    
    for q, a in viva_qa:
        add_callout(doc, q, a, bg_hex="F2F4F8", border_hex="1F3864")

    # ── SECTION 10: STEP-BY-STEP LIVE DEMO GUIDE ─────────────────────────────
    h1 = doc.add_heading("10. Step-by-Step Live Viva Demonstration Script", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    doc.add_paragraph(
        "Follow this exact sequence when demonstrating the live software to your professor or committee:"
    )
    
    demo_steps = [
        ("Step 1: Launch & sign in", "Double-click run_app.bat (or run: streamlit run app.py). Sign in as an analyst — point out the lockout and that every sign-in is audited."),
        ("Step 2: Start a case", "Enter the case number and the recipient (e.g. an investigating officer), press Start case. Note that the analyst is the signed-in account, not typed."),
        ("Step 3: Add evidence", "Show where it came from (device, collector, optional expected hash). Choose Try a sample → clean_system_baseline.csv and point out 'Evidence checked'."),
        ("Step 4: Normal baseline", "Press Analyse evidence. Show the plain-English 'Looks clean' result, then switch on Show technical details to show SHAP drivers pushing towards benign."),
        ("Step 5: Active ransomware", "Switch to fresh_aggressive_ransomware.csv and analyse again. Show the higher risk, the zero-day anomaly flag and the plain-English driver cards; ask the Assistant “explain my result”."),
        ("Step 6: Explainability", "Open the Explainability tab: SHAP shows each feature's contribution; LIME gives independent local rules. Agreement between them increases trust."),
        ("Step 7: Provenance & chain of custody", "Open the Provenance tab (where it came from / who it is for), then Chain of custody: every checkpoint MATCHes the acquisition hash and the ledger is HMAC-linked."),
        ("Step 8: Sealed report", "Download the PDF from the Report tab. Show provenance, verdict, explanations and the ledger, then prove integrity with: certutil -hashfile report.pdf SHA256."),
        ("Step 9: Audit trail", "Sign in as administrator and open Audit log: sign-ins/sign-outs, account changes and all events, with the integrity banner confirming the log has not been altered."),
    ]

    for title, desc in demo_steps:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.2)
        p.paragraph_format.space_after = Pt(4)
        r_t = p.add_run(f"• {title}: ")
        r_t.bold = True
        r_t.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
        p.add_run(desc)

    doc.save(str(DOCX_PATH))
    print(f"[SUCCESS] Successfully compiled Word document at: {DOCX_PATH}")

if __name__ == "__main__":
    build_document()
