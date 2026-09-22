# Memory Forensics AI Triage Dashboard

## Project Overview
This project is a final-year university project focused on building an explainable AI-based memory forensics triage system. The goal is to detect suspicious or malicious memory profiles using machine learning, while also providing analyst-friendly explanations for each prediction.

The system uses:
- Random Forest classification
- Dual XAI framework combining SHAP and LIME
- Streamlit for the interactive dashboard
- Synthetic or uploaded memory feature profiles for testing
- Automated forensic reporting and evidence-gating validation

## Problem Statement
Memory forensics is a critical field in cybersecurity, especially when malware is fileless or memory-resident. Traditional forensic workflows often rely on manual analysis, which can be slow and error-prone. This project explores whether machine learning, combined with explainable AI, can assist investigators in identifying suspicious memory behavior more efficiently.

## Project Objectives
1. Build a machine learning model that classifies memory profiles as benign or malicious.
2. Use a dual XAI framework to generate interpretable explanations for model decisions.
3. Provide a dashboard for analysts to upload memory feature files and review outputs.
4. Simulate adversarial or zero-day-like memory scenarios to evaluate model robustness.
5. Provide automated incident brief generation and pre-flight CSV validation for real-world usability.

## Project Structure

```text
Memory_Forensics_Project/
├── app.py                      # Main Streamlit Forensic Triage Web Dashboard
├── requirements.txt            # Python dependencies
├── README.md                   # Comprehensive project documentation
├── .gitignore                  # Git VCS exclude rules
│
├── data/                       # Forensic datasets & evaluation telemetry
│   ├── Obfuscated-MalMem2022.csv   # Primary benchmark dataset
│   ├── apt_zero_day.csv            # Simulated zero-day memory scenario
│   ├── simulated_cobalt_strike.csv # Simulated memory beaconing dump
│   └── test_samples/               # Curated evaluation profiles for triage testing
│       ├── clean_system_baseline.csv       # Clean OS baseline profile
│       ├── guaranteed_benign.csv           # Validated normal memory profile (~0% risk)
│       ├── guaranteed_malware.csv          # Validated infected memory profile (~100% risk)
│       ├── real_benign_sample.csv          # Authentic unlabelled normal profile
│       ├── fresh_stealth_rootkit.csv       # DKOM / hidden processes threat profile
│       ├── fresh_aggressive_ransomware.csv # High handle spikes threat profile
│       └── fresh_fileless_miner.csv        # Memory code injection & thread max profile
│
├── models/                     # Trained ML model weights
│   ├── random_forest_model.pkl      # Binary classifier (55 memory artifacts)
│   ├── isolation_forest.pkl         # Zero-day unsupervised anomaly detection
│   └── multiclass_random_forest.pkl # Multi-class malware family model
│
├── scripts/                    # Training, evaluation & utility pipelines
│   ├── train_model.py               # Binary Random Forest training pipeline
│   ├── train_multiclass.py          # Multiclass malware family training pipeline
│   ├── evaluate_model.py            # Model comparison, cross-validation & visual metrics
│   ├── benchmark.py                 # Multi-model benchmarking (RF, GBDT, LR)
│   ├── explain_model.py             # SHAP global explainability script
│   ├── test_lime.py                 # LIME local feature attribution validation
│   ├── generate_report.py           # Automated ReportLab PDF brief generator
│   ├── simulate_zeroday.py          # Synthetic zero-day attack simulation
│   ├── generate_synthetic_threats.py # Targeted threat profile generator
│   ├── extract_confident_samples.py # High-confidence sample extractor
│   ├── extract_real_benign.py       # Authentic benign sample extractor
│   ├── verify_data_integrity.py     # Dataset integrity & label leakage auditor
│   └── validate_input.py            # Pre-flight CSV evidence validation
│
├── outputs/                    # Exported incident reports & visual evaluation artifacts
│   ├── *.pdf                        # Official forensic incident reports
│   ├── confusion_matrix.png         # Classification confusion matrix
│   ├── roc_curve.png                # ROC performance curve
│   ├── shap_summary.png             # Global SHAP feature importance plot
│   └── model_comparison.csv         # Comparative algorithm evaluation table
│
└── logs/                       # Immutable forensic audit logs
    └── triage_audit.log             # Tamper-evident chain-of-custody audit ledger
```

## Dataset
The project uses the `Obfuscated-MalMem2022.csv` dataset, which contains memory-derived features used to distinguish benign and malicious samples.

## Setup Instructions
1. Open the project folder.
2. Create a virtual environment if needed.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Train the binary classification model:

```bash
python scripts/train_model.py
```

5. Evaluate the trained model and generate comparison outputs:

```bash
python scripts/evaluate_model.py
```

6. Generate SHAP explanation plots:

```bash
python scripts/explain_model.py
```

7. Run the dashboard:

```bash
streamlit run app.py
```

8. Optional: test LIME explainability, benchmark models, validate input CSV files, or generate the PDF report:

```bash
python scripts/test_lime.py
python scripts/benchmark.py
python scripts/validate_input.py
python scripts/generate_report.py
```

## How the App Works
The dashboard allows users to:
- upload a memory feature CSV file, or
- use a built-in sample from the dataset

After running the triage process, the app provides:
- classification result
- malware probability score
- dual XAI reasoning using SHAP and LIME
- recommended next actions for incident response
- automated PDF reporting for analyst handoff
- pre-flight validation to check input CSV integrity and feature alignment

## Evaluation and Results
The evaluation pipeline generates:
- confusion matrix
- ROC curve
- classification report
- cross-validation metrics
- comparative model performance table

These outputs help validate the performance of the trained models on unseen data and provide evidence for model selection.

## Explainability and XAI Framework
This project uses a Dual XAI Framework to strengthen analyst trust and improve interpretability:
- SHAP is used for global feature attribution and model-level explanation of the overall decision process.
- LIME is used for local instance-level explanations, validating the relevance of individual features for specific predictions.

This transition from a single-framework approach to a dual-framework pipeline is a significant improvement, because it allows the system to validate local feature attributions through both tree-based game-theory reasoning and perturbation-based surrogate modeling.

## Current Strengths
- Clear project workflow and modular architecture
- Use of explainable AI through a dual SHAP + LIME framework
- Interactive user-facing dashboard built with Streamlit
- Comparative benchmarking across multiple models
- Synthetic threat simulation for adversarial and zero-day style evaluation
- Automated PDF forensic incident report generation
- Evidence-gating and pre-flight CSV validation for robust input handling
- Publicly organized repository structure with separated data, models, outputs, and scripts

## Limitations
- The project is currently a prototype rather than a production-ready forensic system.
- The simulated zero-day scenario is useful for demonstration but not a full real-world adversarial evaluation.
- Model performance depends heavily on dataset quality and feature representation.
- Some evaluation and explanation workflows are still tailored to the specific feature schema used in this project.

## Possible Improvements
- Add anomaly detection as a baseline for unseen threats.
- Improve UI flow and result presentation for analyst use cases.
- Extend the framework to support additional memory feature formats.
- Evaluate robustness against evasion tactics and noisy feature sets.
- Expand the system into a formal academic methodology with deeper literature review and statistical interpretation.

## Future Work
- Extend the system to handle more realistic malware memory trace formats from real-world forensic investigations.
- Evaluate robustness against evasion tactics and noisy feature sets.
- Create a formal methodology and literature review section for academic submission.
- Integrate the system with larger forensic pipelines for end-to-end incident response workflows.

## Notes
This project is intended as a practical final-year demonstration and has evolved into a more rigorous academic system by incorporating dual explainability, automated reporting, and evidence validation into the core workflow.
