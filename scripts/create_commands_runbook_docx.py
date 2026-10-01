import os
from pathlib import Path
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

BASE_DIR = Path(__file__).resolve().parent.parent
DOCX_PATH = BASE_DIR / "Memory_Forensics_Commands_And_Execution_Runbook.docx"

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

def add_code_callout(doc, cmd_title, cmd_str, explanation=""):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F2F5F9")
    set_cell_margins(cell, top=100, bottom=100, left=160, right=160)
    
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:left w:val="single" w:sz="24" w:space="0" w:color="1F3864"/>'
        f'<w:top w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'<w:bottom w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    
    r_t = p.add_run(f"⚡ {cmd_title}\n")
    r_t.bold = True
    r_t.font.name = "Calibri"
    r_t.font.size = Pt(10.5)
    r_t.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
    
    r_c = p.add_run(f"{cmd_str}\n")
    r_c.font.name = "Consolas"
    r_c.font.size = Pt(10)
    r_c.bold = True
    r_c.font.color.rgb = RGBColor(0x99, 0x1B, 0x1B) # Crimson red for commands
    
    if explanation:
        r_e = p.add_run(explanation)
        r_e.font.name = "Calibri"
        r_e.font.size = Pt(9.5)
        r_e.font.italic = True
        r_e.font.color.rgb = RGBColor(0x44, 0x44, 0x44)
        
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def format_table(table, col_widths, col_names, data_rows):
    hdr_cells = table.rows[0].cells
    for i, name in enumerate(col_names):
        hdr_cells[i].text = name
        set_cell_background(hdr_cells[i], "1F3864")
        set_cell_margins(hdr_cells[i], top=100, bottom=100, left=120, right=120)
        p = hdr_cells[i].paragraphs[0]
        p.runs[0].font.bold = True
        p.runs[0].font.name = "Calibri"
        p.runs[0].font.size = Pt(9.5)
        p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        
    for row_idx, row_data in enumerate(data_rows):
        row = table.add_row()
        bg_color = "F9FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for col_idx, text in enumerate(row_data):
            cell = row.cells[col_idx]
            cell.text = str(text)
            set_cell_background(cell, bg_color)
            set_cell_margins(cell, top=70, bottom=70, left=120, right=120)
            p = cell.paragraphs[0]
            if len(p.runs) > 0:
                p.runs[0].font.name = "Calibri"
                p.runs[0].font.size = Pt(9)
                p.runs[0].font.color.rgb = RGBColor(0x22, 0x22, 0x22)
                
    for row in table.rows:
        for idx, width in enumerate(col_widths):
            row.cells[idx].width = width

def build_commands_doc():
    doc = docx.Document()
    
    for s in doc.sections:
        s.top_margin = Inches(1)
        s.bottom_margin = Inches(1)
        s.left_margin = Inches(1)
        s.right_margin = Inches(1)
        
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Calibri'
    style_normal.font.size = Pt(11)
    style_normal.font.color.rgb = RGBColor(0x2A, 0x2A, 0x2A)
    
    # Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(0)
    p_title.paragraph_format.space_after = Pt(4)
    r_title = p_title.add_run("MEMORY FORENSICS AI TRIAGE SYSTEM")
    r_title.font.name = "Calibri"
    r_title.font.size = Pt(22)
    r_title.font.bold = True
    r_title.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
    
    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_after = Pt(14)
    r_sub = p_sub.add_run("Complete Command Reference & Script Execution Runbook (CMD & PowerShell)\nEvery command, input argument, expected output, and dashboard launch instruction")
    r_sub.font.name = "Calibri"
    r_sub.font.size = Pt(12)
    r_sub.font.italic = True
    r_sub.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    
    # Meta Box
    meta_table = doc.add_table(rows=1, cols=3)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_cells = meta_table.rows[0].cells
    meta_items = [
        ("Shell Environments", "Windows Command Prompt (cmd) / PowerShell"),
        ("Python Virtual Env", ".\\venv\\Scripts\\python.exe"),
        ("Web Framework", "Streamlit (Local Web Server: 8501)")
    ]
    for idx, (label, val) in enumerate(meta_items):
        cell = meta_cells[idx]
        set_cell_background(cell, "EBF1F5")
        set_cell_margins(cell, top=70, bottom=70, left=90, right=90)
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

    # ── SECTION 1: MASTER CHEAT SHEET ─────────────────────────────────────────
    h1 = doc.add_heading("1. Master Quick-Reference Command Cheat Sheet", level=1)
    h1.paragraph_format.space_before = Pt(10)
    h1.paragraph_format.space_after = Pt(6)
    
    cheat_sheet = [
        ("01", "Launch Web Dashboard", "streamlit run app.py", "Starts the live cyber forensic dashboard on localhost:8501"),
        ("02", "Train Binary Model", "python scripts/train_model.py", "Trains Random Forest on 55 features; outputs random_forest_model.pkl"),
        ("03", "Train Multi-Class Model", "python scripts/train_multiclass.py", "Trains malware family model; outputs multiclass_random_forest.pkl"),
        ("04", "Evaluate & Visualise", "python scripts/evaluate_model.py", "Generates ROC curve, Confusion Matrix, and model_comparison.csv"),
        ("05", "Multi-Model Benchmark", "python scripts/benchmark.py", "5-fold cross-validation benchmarking (RF vs GBDT vs Logistic Reg)"),
        ("06", "Global SHAP Analysis", "python scripts/explain_model.py", "Interrogates AI with TreeSHAP; saves outputs/shap_summary.png"),
        ("07", "Local LIME Validation", "python scripts/test_lime.py", "Generates local surrogate linear decision rules for individual samples"),
        ("08", "Data Integrity Audit", "python scripts/verify_data_integrity.py", "Checks total rows, duplicates, and verifies ZERO label leakage"),
        ("09", "Pre-Flight Evidence Check", "python scripts/validate_input.py", "Validates CSV files for empty rows, missing features, and NaN values"),
        ("10", "Generate Synthetic Threats", "python scripts/generate_synthetic_threats.py", "Generates test profiles: Rootkit (DKOM), Ransomware, Cryptominer"),
        ("11", "Simulate APT Zero-Day", "python scripts/simulate_zeroday.py", "Mutates memory metrics to generate novel threat apt_zero_day.csv"),
        ("12", "Extract Real Baseline", "python scripts/extract_real_benign.py", "Extracts clean workstation profile to real_benign_sample.csv"),
        ("13", "Extract Benchmark Samples", "python scripts/extract_confident_samples.py", "Extracts guaranteed 0% benign and 100% malware test files"),
        ("14", "Generate PDF Report", "python scripts/generate_report.py", "Compiles standalone incident response PDF brief using ReportLab"),
        ("15", "Dataset Sanity Check", "python scripts/test.py", "Quick check of MalMem2022 dataset loading and binary class counts"),
        ("16", "Build Viva Word Doc", "python scripts/create_viva_doc.py", "Compiles comprehensive Viva defense preparation guide (.docx)")
    ]
    
    t_cs = doc.add_table(rows=1, cols=4)
    t_cs.alignment = WD_TABLE_ALIGNMENT.CENTER
    format_table(
        t_cs,
        [Inches(0.4), Inches(1.8), Inches(2.3), Inches(2.5)],
        ["#", "Task Name", "Exact Command to Enter", "Expected Output / Action"],
        cheat_sheet
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # ── SECTION 2: ENVIRONMENT PREPARATION ────────────────────────────────────
    h1 = doc.add_heading("2. Terminal Setup & Environment Activation", level=1)
    h1.paragraph_format.space_before = Pt(12)
    h1.paragraph_format.space_after = Pt(6)
    
    doc.add_paragraph(
        "Before running any script, open your terminal (Command Prompt or PowerShell) and navigate to the project directory:"
    )
    add_code_callout(
        doc,
        "Step 1: Navigate to the Project Root Folder",
        'cd "c:\\Users\\user\\Desktop\\Final resarch\\Memory_Forensics_Project"',
        "Explanation: Ensures all relative filepaths (data/, models/, scripts/, outputs/) resolve correctly."
    )
    
    add_code_callout(
        doc,
        "Step 2A: Activate Virtual Environment in Windows Command Prompt (CMD)",
        "venv\\Scripts\\activate.bat",
        "Explanation: Your prompt will show (venv). All Python commands now use the project's dependencies."
    )
    
    add_code_callout(
        doc,
        "Step 2B: Activate Virtual Environment in Windows PowerShell",
        ".\\venv\\Scripts\\Activate.ps1",
        "Note: If PowerShell displays an 'ExecutionPolicy' security error, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
    )
    
    add_code_callout(
        doc,
        "Alternative: Direct Execution Without Activation (Failsafe)",
        ".\\venv\\Scripts\\python.exe scripts/<script_name>.py",
        "Explanation: Invokes the virtual environment's Python binary directly without needing manual activation."
    )

    # ── SECTION 3: STEP-BY-STEP SCRIPT EXECUTION RUNBOOK ──────────────────────
    h1 = doc.add_heading("3. Detailed Script-by-Script Execution Runbook", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    # 3.1 Web Dashboard
    doc.add_heading("3.1 Launching the Live Forensic Triage Dashboard", level=2)
    add_code_callout(
        doc,
        "Command to Run:",
        "streamlit run app.py",
        "Alternative direct: .\\venv\\Scripts\\streamlit.exe run app.py"
    )
    doc.add_paragraph(
        "• What it does: Starts a local web server hosting the full cyber forensic triage GUI.\n"
        "• URL in Browser: Opens automatically at http://localhost:8501\n"
        "• Expected Console Output:\n"
        "  - You can now view your Streamlit app in your browser.\n"
        "  - Local URL: http://localhost:8501\n"
        "  - Network URL: http://192.168.x.x:8501\n"
        "• How to Stop: Press Ctrl + C in the terminal window."
    )

    # 3.2 Train Binary Model
    doc.add_heading("3.2 Training the Primary Binary Random Forest Classifier", level=2)
    add_code_callout(
        doc,
        "Command to Run:",
        "python scripts/train_model.py",
        "Input Data: data/Obfuscated-MalMem2022.csv"
    )
    doc.add_paragraph(
        "• What it does: Ingests 58,596 memory samples, separates features from Class, splits 80/20, trains 100 decision trees, and evaluates unseen test accuracy.\n"
        "• Output Files Created: models/random_forest_model.pkl\n"
        "• Expected Console Output:\n"
        "  Loading data...\n"
        "  Splitting data into 80% training and 20% testing...\n"
        "  Training the Random Forest model (this might take 10-30 seconds)...\n"
        "  Testing the model...\n"
        "  [+] AI Training Complete!\n"
        "  Model Accuracy: 99.99%\n"
        "  Model saved successfully as 'random_forest_model.pkl'"
    )

    # 3.3 Train Multi-Class Model
    doc.add_heading("3.3 Training Multi-Class Malware Family Classification", level=2)
    add_code_callout(
        doc,
        "Command to Run:",
        "python scripts/train_multiclass.py",
        "Identifies specific malware categories (Spyware, Ransomware, Trojan)"
    )
    doc.add_paragraph(
        "• What it does: Parses malware family prefix names from the Category column, maps them to integers (0=Benign, 1=Spyware, 2=Ransomware, 3=Trojan), trains a 100-tree Multi-Class Random Forest, and displays precision/recall for every family.\n"
        "• Output Files Created: models/multiclass_random_forest.pkl\n"
        "• Expected Console Output:\n"
        "  Parsed Malware Family Distribution:\n"
        "  Benign: 29,298 | Ransomware: 9,791 | Trojan: 9,728 | Spyware: 9,779\n"
        "  Training Multi-Class Random Forest across malware families...\n"
        "  Multi-Class Classification Report on Unseen Test Data:\n"
        "  Macro avg F1-Score: > 85%\n"
        "  [+] Saved model as 'multiclass_random_forest.pkl'"
    )

    # 3.4 Academic Model Evaluation
    doc.add_heading("3.4 Academic Model Evaluation & Visual Artifacts Generation", level=2)
    add_code_callout(
        doc,
        "Command to Run:",
        "python scripts/evaluate_model.py",
        "Generates publication-quality charts and comparative statistics"
    )
    doc.add_paragraph(
        "• What it does: Runs Stratified 3-Fold Cross-Validation, compares Random Forest against a regularized Logistic Regression baseline, and renders visual evaluation plots.\n"
        "• Output Files Created:\n"
        "  - outputs/model_comparison.csv (Full metrics comparison table)\n"
        "  - outputs/confusion_matrix.png (Blues confusion matrix plot)\n"
        "  - outputs/roc_curve.png (Receiver Operating Characteristic plot, AUC=1.0000)\n"
        "  - models/random_forest_model.pkl (Refreshed best model)\n"
        "• Expected Console Output:\n"
        "  [1/5] Loading and preparing dataset...\n"
        "  [2/5] Performing stratified 80/20 train-test split...\n"
        "  [3/5] Training and evaluating multiple models...\n"
        "  Evaluating Logistic Regression -> Mean CV ROC-AUC: 99.99%\n"
        "  Evaluating Random Forest -> Mean CV ROC-AUC: 100.00%\n"
        "  [4/5] Best performing model on unseen data: Random Forest\n"
        "  [5/5] Generating best-model visual outputs..."
    )

    # 3.5 Comparative Benchmarking
    doc.add_heading("3.5 Multi-Model Benchmarking Across 5 Folds", level=2)
    add_code_callout(
        doc,
        "Command to Run:",
        "python scripts/benchmark.py",
        "Cross-validates Random Forest, Gradient Boosting, and Logistic Regression"
    )
    doc.add_paragraph(
        "• What it does: Runs a 5-fold Stratified cross-validation race between 3 standard classification algorithms.\n"
        "• Expected Console Output:\n"
        "  Evaluating Random Forest across 5 folds... Mean F1-Score: ~99.98%\n"
        "  Evaluating Gradient Boosting across 5 folds... Mean F1-Score: ~99.96%\n"
        "  Evaluating Logistic Regression across 5 folds... Mean F1-Score: ~99.85%\n"
        "  --- Benchmark Summary ---\n"
        "  Proves Random Forest provides highest stability and F1-score."
    )

    # 3.6 Explain Model (SHAP)
    doc.add_heading("3.6 Generating Global Explainable AI (SHAP) Attribution Plot", level=2)
    add_code_callout(
        doc,
        "Command to Run:",
        "python scripts/explain_model.py",
        "Calculates cooperative game-theoretic Shapley values"
    )
    doc.add_paragraph(
        "• What it does: Loads the trained Random Forest brain, takes 100 representative memory samples, computes Shapley values via TreeExplainer, and saves a global feature attribution graph.\n"
        "• Output Files Created: outputs/shap_summary.png\n"
        "• Expected Console Output:\n"
        "  Loading saved AI model...\n"
        "  Loading dataset for explanation...\n"
        "  Interrogating the AI with SHAP...\n"
        "  Creating visual explanation plot...\n"
        "  [+] Explainable AI plot saved successfully as 'outputs/shap_summary.png'!"
    )

    # 3.7 Local Explainability (LIME)
    doc.add_heading("3.7 Testing Local Interpretable Model-agnostic Explanations (LIME)", level=2)
    add_code_callout(
        doc,
        "Command to Run:",
        "python scripts/test_lime.py",
        "Generates local linear surrogate decision rules"
    )
    doc.add_paragraph(
        "• What it does: Fits a LimeTabularExplainer, selects a malware profile, perturbs memory features 1,000 times, and outputs the top 5 local decision rules driving the prediction.\n"
        "• Expected Console Output:\n"
        "  LIME Local Explanation for Instance #32:\n"
        "  - handles.avg_handles_per_proc > 9800: +0.3421 (Toward Malware)\n"
        "  - malfind.ninjections > 0: +0.2814 (Toward Malware)\n"
        "  - psxview.not_in_eprocess > 0: +0.1980 (Toward Malware)\n"
        "  [+] LIME explainer successfully executed!"
    )

    # 3.8 Dataset Integrity & Pre-Flight Validation
    doc.add_heading("3.8 Auditing Data Integrity & Pre-Flight Evidence Checks", level=2)
    add_code_callout(
        doc,
        "Command 1: Dataset Integrity & Leakage Auditor",
        "python scripts/verify_data_integrity.py",
        "Checks for target label leakage and duplicate samples"
    )
    doc.add_paragraph(
        "• Expected Output:\n"
        "  --- DATASET INTEGRITY AUDIT ---\n"
        "  Total Rows: 58,596\n"
        "  Duplicate Rows: 0\n"
        "  Ground Truth Label Columns Detected: ['Class', 'Category']\n"
        "  Clean Independent Features Count: 55"
    )
    
    add_code_callout(
        doc,
        "Command 2: Pre-Flight Evidence-Gating Checker",
        "python scripts/validate_input.py",
        "Validates test CSV files for schema alignment and nulls"
    )
    doc.add_paragraph(
        "• Expected Output:\n"
        "  Validation Report for 'simulated_cobalt_strike.csv':\n"
        "  Status: PASS\n"
        "  Missing features: 0 | Null values: 0"
    )

    # 3.9 Threat Generation & Test Samples
    doc.add_heading("3.9 Generating Threat Profiles & Extracting Baselines", level=2)
    add_code_callout(
        doc,
        "Command 1: Generate Fresh Targeted Threat Scenarios",
        "python scripts/generate_synthetic_threats.py",
        "Creates DKOM Rootkit, Ransomware, and Cryptominer profiles"
    )
    doc.add_paragraph(
        "• Output Files Created in data/test_samples/:\n"
        "  - fresh_stealth_rootkit.csv (Focus: psxview.not_in_eprocess unlinked process)\n"
        "  - fresh_aggressive_ransomware.csv (Focus: handles.avg_handles_per_proc spike)\n"
        "  - fresh_fileless_miner.csv (Focus: malfind.ninjections & thread max)"
    )
    
    add_code_callout(
        doc,
        "Command 2: Simulate Adversarial Zero-Day Scenario",
        "python scripts/simulate_zeroday.py",
        "Mutates genuine malware features to test out-of-distribution resilience"
    )
    doc.add_paragraph(
        "• Output File Created: data/apt_zero_day.csv"
    )
    
    add_code_callout(
        doc,
        "Command 3: Extract Authentic Clean Host Baseline",
        "python scripts/extract_real_benign.py",
        "Strips labels and extracts clean workstation memory profile"
    )
    doc.add_paragraph(
        "• Output File Created: data/test_samples/real_benign_sample.csv"
    )

    # 3.10 PDF Reporting & Test Builders
    doc.add_heading("3.10 Compiling Forensic Incident Reports (PDF & DOCX)", level=2)
    add_code_callout(
        doc,
        "Command 1: Generate Standalone Forensic PDF Dossier",
        "python scripts/generate_report.py",
        "Compiles official incident brief with indicators and playbook"
    )
    doc.add_paragraph(
        "• Output File Created: outputs/forensic_triage_report.pdf"
    )
    
    add_code_callout(
        doc,
        "Command 2: Test Full XAI PDF Report Builder",
        "python scripts/test_pdf_builder.py",
        "Validates ReportLab rendering with SHAP and LIME tables"
    )
    doc.add_paragraph(
        "• Output File Created: outputs/test_full_xai_report.pdf"
    )

    add_code_callout(
        doc,
        "Command 3: Compile Complete Viva Defense Guide (.docx)",
        "python scripts/create_viva_doc.py",
        "Generates the full comprehensive Viva guide Word document"
    )
    doc.add_paragraph(
        "• Output File Created: Memory_Forensics_AI_Triage_Viva_Defense_Guide.docx"
    )

    # ── SECTION 4: TROUBLESHOOTING & COMMON MISTAKES ─────────────────────────
    h1 = doc.add_heading("4. Troubleshooting & Common Terminal Errors", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)
    
    tb_data = [
        (
            "Error: 'streamlit is not recognized as an internal or external command'",
            "Virtual environment is not active or Streamlit was installed in a different Python path.",
            "Solution:\nRun via the python module syntax:\n.\\venv\\Scripts\\python.exe -m streamlit run app.py"
        ),
        (
            "Error: 'Script execution is disabled on this system' (PowerShell)",
            "Windows PowerShell blocks script execution by default for security.",
            "Solution:\nSet-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass\nThen re-run: .\\venv\\Scripts\\Activate.ps1"
        ),
        (
            "Error: 'Port 8501 is already in use'",
            "Another instance of the Streamlit dashboard is already running in the background.",
            "Solution:\nLaunch on an alternate port:\nstreamlit run app.py --server.port 8502"
        ),
        (
            "Error: 'FileNotFoundError: data/Obfuscated-MalMem2022.csv'",
            "Terminal working directory is wrong (you ran the command from inside scripts/ instead of project root).",
            "Solution:\ncd \"c:\\Users\\user\\Desktop\\Final resarch\\Memory_Forensics_Project\"\nAlways run scripts from the project root."
        )
    ]
    t_tb = doc.add_table(rows=1, cols=3)
    t_tb.alignment = WD_TABLE_ALIGNMENT.CENTER
    format_table(
        t_tb,
        [Inches(2.2), Inches(2.2), Inches(2.6)],
        ["Observed Terminal Error", "Root Cause Analysis", "Exact Recovery Command / Solution"],
        tb_data
    )

    doc.save(str(DOCX_PATH))
    print(f"[SUCCESS] Successfully compiled Commands Runbook at: {DOCX_PATH}")

if __name__ == "__main__":
    build_commands_doc()
