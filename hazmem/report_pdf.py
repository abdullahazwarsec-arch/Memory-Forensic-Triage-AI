"""
Sealed PDF incident report (ReportLab): provenance, verdict, SHAP/LIME
explanations, response actions and the full chain-of-custody ledger.
"""

import html
import logging
import os
import re
from datetime import datetime

import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage

from . import evidence_integrity as ei
from . import ui_theme as ui
from .knowledge import RESPONSE_ACTIONS, recipient_label

REPORTS_DIR = os.path.join("outputs", "reports")   # set by app.py
logger = logging.getLogger("triage")


# ── SECTION 9: PDF REPORT GENERATOR ──────────────────────────────────────────

def generate_pdf_report(result: dict, shap_df: pd.DataFrame = None, lime_df: pd.DataFrame = None,
                        chain: "ei.CustodyChain" = None):
    """
    Build a comprehensive forensic PDF incident brief and save it to outputs/.
    Returns (output_path, pdf_bytes) so the dashboard can offer immediate download.
    Includes full explainability findings (SHAP global attribution + LIME local rules)
    translated into plain English for non-technical users and forensic investigators.
    """
    timestamp_clean = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename        = f"forensic_report_{result['evidence_id']}_{timestamp_clean}.pdf"
    output_path     = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    styles = getSampleStyleSheet()

    # Custom Report Typography
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=15,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=8
    )
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=6,
        spaceAfter=3
    )
    cell_style = ParagraphStyle(
        'CellNorm',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#334155')
    )
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1E293B')
    )
    cell_danger = ParagraphStyle(
        'CellDanger',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#DC2626')
    )
    cell_warning = ParagraphStyle(
        'CellWarning',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#D97706')
    )
    cell_normal = ParagraphStyle(
        'CellNormal',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#16A34A')
    )

    cell_header = ParagraphStyle('CellHeader', parent=cell_bold, textColor=colors.white)

    def xml_esc(val):
        """Escape XML entities for ReportLab Paragraph rendering."""
        return html.escape(str(val) if val is not None else "", quote=False)

    story = []

    # ── Header ────────────────────────────────────────────────
    brand = Table([[RLImage(ui.LOGO_PNG, width=46, height=46),
                    [Paragraph("HAZMEM &bull; MEMORY FORENSIC TRIAGE &amp; XAI INVESTIGATION REPORT", title_style),
                     Paragraph("Explainable AI Memory Forensics &bull; Chain-of-Custody Verified &bull; Confidential",
                               subtitle_style)]]], colWidths=[56, None])
    brand.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(brand)

    # ── 1. Chain of custody ───────────────────────────────────
    story.append(Paragraph("1. Chain of Custody &amp; Evidence Metadata", h2_style))
    r_idx = result["row_index"]
    n_feat = len(result.get("feature_cols", []))
    integ = result.get("integrity", {}) or {}
    hash_style = ParagraphStyle('HashMono', parent=cell_style, fontName='Courier', fontSize=7.2, leading=9)
    meta_data = [
        [Paragraph("Case Number", cell_bold), Paragraph(xml_esc(integ.get("case_id", "N/A")), cell_style)],
        [Paragraph("Examiner / Analyst", cell_bold), Paragraph(
            xml_esc(integ.get("analyst", "N/A") + (f" ({integ['organisation']})" if integ.get("organisation") else "")),
            cell_style)],
        [Paragraph("Case Session", cell_bold), Paragraph(
            xml_esc(f"{integ.get('session_id', '')} - opened {integ.get('session_opened', '')}"), cell_style)],
        [Paragraph("Evidence Item ID", cell_bold), Paragraph(xml_esc(integ.get("evidence_item_id", "N/A")), cell_style)],
        [Paragraph("Analysis ID", cell_bold), Paragraph(xml_esc(result["evidence_id"]), cell_style)],
        [Paragraph("Analysis Timestamp", cell_bold), Paragraph(xml_esc(result["timestamp"]), cell_style)],
        [Paragraph("Source Evidence File", cell_bold), Paragraph(
            f"{xml_esc(result['source_file'])} ({xml_esc(integ.get('evidence_kind', ''))}, "
            f"{ei.format_size(integ.get('evidence_size', 0) or 0)})", cell_style)],
        [Paragraph("Evidence Origin", cell_bold), Paragraph(xml_esc(
            (lambda o: f"{o.get('source_device', 'N/A')}"
                       f"{(' - custodian ' + o['custodian']) if o.get('custodian') else ''}"
                       f"{(' - ' + o['location']) if o.get('location') else ''}")(
                (integ.get("provenance") or {}).get("origin") or {})), cell_style)],
        [Paragraph("Collected By / When / Tool", cell_bold), Paragraph(xml_esc(
            (lambda o: f"{o.get('collected_by', 'N/A')} - {o.get('collected_at', 'N/A')} - "
                       f"{o.get('acquisition_tool', 'N/A')}")(
                (integ.get("provenance") or {}).get("origin") or {})), cell_style)],
        [Paragraph("Prepared For", cell_bold), Paragraph(xml_esc(
            (lambda r: f"{recipient_label(r)} - {r.get('purpose', 'N/A')}"
                       f"{(' - ref ' + r['reference']) if r.get('reference') else ''}")(
                (integ.get("provenance") or {}).get("prepared_for") or {})), cell_style)],
        [Paragraph("Evidence SHA-256", cell_bold), Paragraph(xml_esc(integ.get("evidence_sha256", "N/A")), hash_style)],
        [Paragraph("Evidence MD5", cell_bold), Paragraph(xml_esc(integ.get("evidence_md5", "N/A")), hash_style)],
    ]
    if integ.get("csv_sha256"):
        meta_data.append([Paragraph("Derived Feature CSV SHA-256", cell_bold), Paragraph(
            f"{xml_esc(integ['csv_sha256'])}<br/><font face='Helvetica'>{xml_esc(integ.get('csv_name', ''))}</font>",
            hash_style)])
    meta_data += [
        [Paragraph("Analysed Vector SHA-256", cell_bold), Paragraph(xml_esc(integ.get("vector_sha256", "N/A")), hash_style)],
        [Paragraph("Evaluated Record / Row", cell_bold), Paragraph(f"Row {r_idx}", cell_style)],
        [Paragraph("Telemetry Features", cell_bold), Paragraph(f"{n_feat} memory telemetry indicators", cell_style)],
        [Paragraph("Input Validation", cell_bold), Paragraph(xml_esc(integ.get("input_validation") or "N/A"),
                                                              cell_style if integ.get("input_validation", "").startswith("PASSED")
                                                              else cell_warning)],
        [Paragraph("Analysis Engines", cell_bold), Paragraph("Random Forest Classifier (150 trees) + Isolation Forest (Zero-Day Anomaly Detector)", cell_style)],
    ]
    if chain is not None:
        n_match = sum(e["status"] == ei.STATUS_MATCH for e in chain.events)
        integrity_text = (
            f"VERIFIED - {n_match} re-verification(s) across {len(chain.events)} custody checkpoints match the "
            f"acquisition hashes; ledger hash-links intact. Evidence was not modified by this tool."
            if chain.is_intact else
            "COMPROMISED - one or more hash re-verifications did not match. See Section 7."
        )
        meta_data.append([Paragraph("Integrity Status", cell_bold),
                          Paragraph(xml_esc(integrity_text), cell_normal if chain.is_intact else cell_danger)])
    meta_table = Table(meta_data, colWidths=[140, 400])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # ── 2. Verdict ────────────────────────────────────────────
    story.append(Paragraph("2. Automated Forensic Triage Verdict", h2_style))
    risk_style = (
        cell_danger if result["risk"] == "HIGH RISK" else
        cell_warning if result["risk"] == "SUSPICIOUS" else
        cell_normal
    )
    anomaly_text = (
        "ANOMALY DETECTED (Memory profile deviates significantly from known baseline - potential zero-day)"
        if result.get("is_anomaly")
        else "No novel memory anomaly detected (consistent with baseline distributions)"
    )
    anomaly_style = cell_danger if result.get("is_anomaly") else cell_style
    p_conf = result["probability"] * 100

    verdict_data = [
        [Paragraph("Risk Classification", cell_bold), Paragraph(xml_esc(result["risk"]), risk_style)],
        [Paragraph("Malware Confidence", cell_bold), Paragraph(f"{p_conf:.2f}%", cell_style)],
        [Paragraph("Primary Prediction", cell_bold), Paragraph("MALWARE" if result["prediction"] else "BENIGN", risk_style)],
        [Paragraph("Zero-Day Anomaly Check", cell_bold), Paragraph(xml_esc(anomaly_text), anomaly_style)],
    ]
    verdict_table = Table(verdict_data, colWidths=[140, 400])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 6))

    # ── 3. SHAP ───────────────────────────────────────────────
    story.append(Paragraph("3. Explainable AI: Key Decision Drivers (SHAP Global Attribution)", h2_style))
    if shap_df is not None and not shap_df.empty:
        shap_table_data = [
            [
                Paragraph("Plain-English Indicator", cell_header),
                Paragraph("Telemetry Metric", cell_header),
                Paragraph("Verdict Impact", cell_header),
                Paragraph("Forensic Meaning &amp; Threat Danger", cell_header)
            ]
        ]
        for _, row in shap_df.head(5).iterrows():
            is_mal = row["SHAP Value"] > 0
            imp_style = cell_danger if is_mal else cell_normal
            sv = row["SHAP Value"] * 100
            imp_text = f"+{sv:.1f}% (Malware)" if is_mal else f"{sv:.1f}% (Benign)"
            desc = row.get("What This Is", "")
            dng = row.get("Forensic Context", "")
            explanation = f"{desc} Threat Context: {dng}"
            shap_table_data.append([
                Paragraph(xml_esc(row["Plain English Indicator"]), cell_bold),
                Paragraph(xml_esc(row["Technical Metric"]), cell_style),
                Paragraph(imp_text, imp_style),
                Paragraph(xml_esc(explanation), cell_style),
            ])
        shap_table = Table(shap_table_data, colWidths=[130, 95, 95, 220])
        shap_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(shap_table)
    else:
        story.append(Paragraph("SHAP global attribution details not available for this run.", cell_style))
    story.append(Spacer(1, 6))

    # ── 4. LIME ───────────────────────────────────────────────
    story.append(Paragraph("4. Explainable AI: Corroborating Evidence (LIME Local Rules)", h2_style))
    if lime_df is not None and not lime_df.empty:
        lime_table_data = [
            [
                Paragraph("Plain-English Indicator", cell_header),
                Paragraph("Observed Telemetry Rule", cell_header),
                Paragraph("Local Weight", cell_header),
                Paragraph("Forensic Interpretation", cell_header)
            ]
        ]
        for _, row in lime_df.head(4).iterrows():
            is_mal = row["LIME Weight"] > 0
            w_style = cell_danger if is_mal else cell_normal
            lw = row["LIME Weight"] * 100
            w_text = f"+{lw:.1f}% (Malware)" if is_mal else f"{lw:.1f}% (Benign)"
            obs_cond = str(row.get("Observed Condition", ""))
            desc = row.get("What This Means", "")
            dng = row.get("Forensic Context", "")
            explanation = f"{desc} Danger: {dng}"
            lime_table_data.append([
                Paragraph(xml_esc(row["Plain English Indicator"]), cell_bold),
                Paragraph(xml_esc(obs_cond), cell_style),
                Paragraph(w_text, w_style),
                Paragraph(xml_esc(explanation), cell_style),
            ])
        lime_table = Table(lime_table_data, colWidths=[130, 110, 80, 220])
        lime_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(lime_table)
    else:
        story.append(Paragraph("LIME local decision rule data not available for this run.", cell_style))
    story.append(Spacer(1, 6))

    # ── 5. Incident response ──────────────────────────────────
    story.append(Paragraph("5. Recommended Incident Response Playbook", h2_style))
    actions = RESPONSE_ACTIONS.get(result["risk"], [])
    for act in actions:
        clean_act = re.sub(r'^[^\w\s]+', '', act).strip()
        story.append(Paragraph(f"&bull; {xml_esc(clean_act)}", cell_style))
    story.append(Spacer(1, 6))

    # ── 6. Disclaimer ─────────────────────────────────────────
    story.append(Paragraph("6. Legal &amp; Forensic Disclaimer", h2_style))
    story.append(Paragraph(
        "This triage report is generated by an Explainable AI Memory Forensics System to assist incident "
        "responders and forensic investigators. Automated assessments do not constitute sole definitive "
        "legal evidence. All findings must be corroborated by a qualified human forensic analyst.",
        cell_style
    ))

    # ── 7. Evidence integrity ledger ──────────────────────────
    if chain is not None:
        story.append(Spacer(1, 6))
        story.append(Paragraph("7. Evidence Integrity Verification &amp; Chain-of-Custody Ledger", h2_style))
        story.append(Paragraph(
            "Every artefact handled by the tool was hashed (SHA-256) when first received and re-hashed at each "
            "processing stage. MATCH means the recomputed hash equals the hash recorded at acquisition. Each "
            "ledger entry is chained to the previous entry by an HMAC-SHA256 link keyed with the lab's secret "
            f"ledger key (key ID {xml_esc(ei.ledger_key_id())}), so the ledger cannot be altered and re-chained "
            "without that key.",
            cell_style
        ))
        story.append(Spacer(1, 4))
        ledger_style = ParagraphStyle('Ledger', parent=cell_style, fontSize=6.6, leading=8.2)
        ledger_hash  = ParagraphStyle('LedgerHash', parent=ledger_style, fontName='Courier', fontSize=6.2, leading=7.8)
        ledger_data = [[Paragraph(h, cell_bold) for h in ("#", "Time (UTC)", "Stage / Action", "Artefact", "SHA-256", "Status")]]
        status_styles = {ei.STATUS_MATCH: cell_normal, ei.STATUS_MISMATCH: cell_danger, ei.STATUS_MISSING: cell_warning}
        for e in chain.events:
            ledger_data.append([
                Paragraph(str(e["seq"]), ledger_style),
                Paragraph(xml_esc(e["timestamp"].replace(" UTC", "")), ledger_style),
                Paragraph(f"<b>{xml_esc(e['stage'])}</b><br/>{xml_esc(e['action'])}", ledger_style),
                Paragraph(xml_esc(e["artifact"]), ledger_style),
                Paragraph(xml_esc(e["sha256"] or "-"), ledger_hash),
                Paragraph(xml_esc(e["status"]), status_styles.get(e["status"], cell_bold)),
            ])
        ledger_table = Table(ledger_data, colWidths=[18, 62, 150, 85, 165, 60], repeatRows=1)
        ledger_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(ledger_table)
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Ledger head hash: <font face='Courier'>{xml_esc(chain.head_hash)}</font><br/>"
            "Report seal: a document cannot contain its own hash. The SHA-256 of this PDF is computed immediately "
            "after generation and recorded in the custody manifest (custody_manifest.json), the audit log "
            "(logs/triage_audit.log) and a '&lt;report&gt;.pdf.sha256' sidecar file. To verify this copy, run "
            "<font face='Courier'>certutil -hashfile &lt;report.pdf&gt; SHA256</font> (Windows) or "
            "<font face='Courier'>sha256sum &lt;report.pdf&gt;</font> and compare with those records.",
            cell_style
        ))

    # ── Examiner declaration ──────────────────────────────────
    story.append(Spacer(1, 10))
    story.append(Paragraph("Examiner Declaration", h2_style))
    story.append(Paragraph(
        f"I, {xml_esc(integ.get('analyst', '________________'))}, examined the evidence listed above under case "
        f"{xml_esc(integ.get('case_id', '________'))}. The findings in this report were produced by the tool "
        "and reviewed by me.", cell_style))
    story.append(Spacer(1, 16))
    story.append(Paragraph("Signature: ______________________________ &nbsp;&nbsp;&nbsp; Date: ________________", cell_style))

    # Build document
    doc.build(story)

    # Read binary bytes for Streamlit download button
    with open(output_path, "rb") as f:
        pdf_bytes = f.read()

    logger.info(f"PDF report saved: {output_path} | EVIDENCE_ID={result['evidence_id']}")
    return output_path, pdf_bytes
