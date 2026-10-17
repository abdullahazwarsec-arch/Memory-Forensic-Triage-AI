import os
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def test_builder():
    OUTPUT_DIR = "outputs"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "test_full_xai_report.pdf")

    result = {
        'timestamp': '2026-09-22 19:10:00',
        'evidence_id': 'TEST_FULL_EVID',
        'source_file': 'sample_memory.csv',
        'row_index': 0,
        'risk': 'HIGH RISK',
        'probability': 0.892,
        'prediction': 1,
        'is_anomaly': True,
        'feature_cols': ['svcscan.nservices', 'handles.avg_handles_per_proc', 'malfind.ninjections']
    }

    shap_df = pd.DataFrame([
        {
            'Plain English Indicator': 'Windows System Services Count',
            'Technical Metric': 'svcscan.nservices',
            'SHAP Value': 0.312,
            'What This Is': 'Count of background services registered in the database.',
            'Forensic Context': 'Malware registers services for persistence.'
        },
        {
            'Plain English Indicator': 'Direct Memory Code Injections',
            'Technical Metric': 'malfind.ninjections',
            'SHAP Value': 0.245,
            'What This Is': 'Executable memory regions unbacked by files on disk.',
            'Forensic Context': 'Fileless malware, Cobalt Strike beacons, or shellcode.'
        }
    ])

    lime_df = pd.DataFrame([
        {
            'Plain English Indicator': 'Direct Memory Code Injections',
            'Observed Condition': 'malfind.ninjections > 0.00',
            'LIME Weight': 0.28,
            'What This Means': 'Code floating in memory without disk backing.',
            'Forensic Context': 'Severe memory injection indicator.'
        }
    ])

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=15, leading=18, textColor=colors.HexColor('#1E293B'), spaceAfter=2)
    subtitle_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor('#64748B'), spaceAfter=8)
    h2_style = ParagraphStyle('DocH2', parent=styles['Heading2'], fontSize=10, leading=13, textColor=colors.HexColor('#0F172A'), spaceBefore=6, spaceAfter=3)
    cell_style = ParagraphStyle('CellNorm', parent=styles['Normal'], fontSize=7.5, leading=9.5, textColor=colors.HexColor('#334155'))
    cell_bold = ParagraphStyle('CellBold', parent=styles['Normal'], fontSize=7.5, leading=9.5, fontName='Helvetica-Bold', textColor=colors.HexColor('#1E293B'))
    cell_danger = ParagraphStyle('CellDanger', parent=styles['Normal'], fontSize=7.5, leading=9.5, fontName='Helvetica-Bold', textColor=colors.HexColor('#DC2626'))
    cell_warning = ParagraphStyle('CellWarning', parent=styles['Normal'], fontSize=7.5, leading=9.5, fontName='Helvetica-Bold', textColor=colors.HexColor('#D97706'))
    cell_normal = ParagraphStyle('CellNormal', parent=styles['Normal'], fontSize=7.5, leading=9.5, fontName='Helvetica-Bold', textColor=colors.HexColor('#16A34A'))

    doc = SimpleDocTemplate(out_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    story = []

    story.append(Paragraph('MEMORY FORENSIC TRIAGE &amp; XAI INVESTIGATION REPORT', title_style))
    story.append(Paragraph('Explainable AI Memory Forensics Framework &bull; Incident Triage Brief &bull; Confidential', subtitle_style))

    # 1. Chain of custody
    story.append(Paragraph('1. Chain of Custody &amp; Evidence Metadata', h2_style))
    r_idx = result['row_index']
    n_feat = len(result.get('feature_cols', []))
    meta_data = [
        [Paragraph('Evidence ID', cell_bold), Paragraph(str(result['evidence_id']), cell_style)],
        [Paragraph('Analysis Timestamp', cell_bold), Paragraph(str(result['timestamp']), cell_style)],
        [Paragraph('Source Memory File', cell_bold), Paragraph(str(result['source_file']), cell_style)],
        [Paragraph('Evaluated Record / Row', cell_bold), Paragraph(f'Row {r_idx}', cell_style)],
        [Paragraph('Telemetry Features', cell_bold), Paragraph(f'{n_feat} memory telemetry indicators', cell_style)],
        [Paragraph('Analysis Engines', cell_bold), Paragraph('Random Forest Classifier (150 trees) + Isolation Forest (Anomaly Detector)', cell_style)],
    ]
    meta_table = Table(meta_data, colWidths=[140, 400])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # 2. Verdict
    story.append(Paragraph('2. Automated Forensic Triage Verdict', h2_style))
    risk_style = cell_danger if result['risk'] == 'HIGH RISK' else (cell_warning if result['risk'] == 'SUSPICIOUS' else cell_normal)
    anomaly_text = 'ANOMALY DETECTED (Memory profile deviates from known baseline - zero-day risk)' if result.get('is_anomaly') else 'No novel memory anomaly detected (consistent with baseline)'
    anomaly_style = cell_danger if result.get('is_anomaly') else cell_style
    p_conf = result['probability'] * 100

    verdict_data = [
        [Paragraph('Risk Classification', cell_bold), Paragraph(str(result['risk']), risk_style)],
        [Paragraph('Malware Confidence', cell_bold), Paragraph(f'{p_conf:.2f}%', cell_style)],
        [Paragraph('Primary Prediction', cell_bold), Paragraph('MALWARE' if result['prediction'] else 'BENIGN', risk_style)],
        [Paragraph('Zero-Day Anomaly Check', cell_bold), Paragraph(anomaly_text, anomaly_style)],
    ]
    verdict_table = Table(verdict_data, colWidths=[140, 400])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 6))

    # 3. SHAP
    story.append(Paragraph('3. Explainable AI: Key Decision Drivers (SHAP Global Attribution)', h2_style))
    shap_table_data = [
        [Paragraph('Plain-English Indicator', cell_bold), Paragraph('Telemetry Metric', cell_bold), Paragraph('Verdict Impact', cell_bold), Paragraph('Forensic Meaning &amp; Threat Danger', cell_bold)]
    ]
    for _, row in shap_df.head(5).iterrows():
        is_mal = row['SHAP Value'] > 0
        imp_style = cell_danger if is_mal else cell_normal
        sv = row['SHAP Value'] * 100
        imp_text = f'+{sv:.1f}% (Malware)' if is_mal else f'{sv:.1f}% (Benign)'
        shap_table_data.append([
            Paragraph(str(row['Plain English Indicator']), cell_bold),
            Paragraph(str(row['Technical Metric']), cell_style),
            Paragraph(imp_text, imp_style),
            Paragraph(f"{row.get('What This Is', '')} Threat Context: {row.get('Forensic Context', '')}", cell_style),
        ])
    shap_table = Table(shap_table_data, colWidths=[130, 95, 95, 220])
    shap_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(shap_table)
    story.append(Spacer(1, 6))

    # 4. LIME
    story.append(Paragraph('4. Explainable AI: Corroborating Evidence (LIME Local Rules)', h2_style))
    lime_table_data = [
        [Paragraph('Plain-English Indicator', cell_bold), Paragraph('Observed Telemetry Rule', cell_bold), Paragraph('Local Weight', cell_bold), Paragraph('Forensic Interpretation', cell_bold)]
    ]
    for _, row in lime_df.head(4).iterrows():
        is_mal = row['LIME Weight'] > 0
        w_style = cell_danger if is_mal else cell_normal
        lw = row['LIME Weight'] * 100
        w_text = f'+{lw:.1f}% (Malware)' if is_mal else f'{lw:.1f}% (Benign)'
        obs_cond = str(row.get('Observed Condition', '')).replace('<', '&lt;').replace('>', '&gt;')
        lime_table_data.append([
            Paragraph(str(row['Plain English Indicator']), cell_bold),
            Paragraph(obs_cond, cell_style),
            Paragraph(w_text, w_style),
            Paragraph(f"{row.get('What This Means', '')} Danger: {row.get('Forensic Context', '')}", cell_style),
        ])
    lime_table = Table(lime_table_data, colWidths=[130, 110, 80, 220])
    lime_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(lime_table)
    story.append(Spacer(1, 6))

    # 5. Playbook
    story.append(Paragraph('5. Recommended Incident Response Playbook', h2_style))
    actions = [
        'Isolate endpoint from network immediately',
        'Preserve full memory dump using Volatility3 or WinPmem',
        'Extract and hash all injected process regions',
        'Escalate to Tier 2 analyst and open incident ticket',
        'Correlate with SIEM and threat intelligence feeds'
    ]
    for act in actions:
        story.append(Paragraph(f'&bull; {act}', cell_style))
    story.append(Spacer(1, 6))

    # 6. Disclaimer
    story.append(Paragraph('6. Legal &amp; Forensic Disclaimer', h2_style))
    story.append(Paragraph(
        'This triage report is generated by an Explainable AI Memory Forensics System to assist incident '
        'responders and forensic investigators. Automated assessments do not constitute sole definitive '
        'legal evidence. All findings must be corroborated by a qualified human forensic analyst.',
        cell_style
    ))

    doc.build(story)
    with open(out_path, 'rb') as f:
        pdf_bytes = f.read()

    print(f'Test PDF built successfully! Size: {len(pdf_bytes)} bytes')

if __name__ == '__main__':
    test_builder()
