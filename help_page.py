"""
Help & glossary page: a plain-English guide for analysts who are new to the
dashboard or to memory forensics.
"""

import streamlit as st

import auth
import ui_theme as ui


GLOSSARY = [
    ("Memory dump", "A copy of everything that was in a computer's RAM at one moment. Malware that never touches "
                    "the disk (\"fileless\") can only be found here."),
    ("Volatility", "The open-source tool that reads a memory dump and lists processes, DLLs, handles, services and "
                   "injected code. The dashboard turns its output into 55 numeric features."),
    ("Feature", "One measurement taken from memory, e.g. the number of running processes or of injected code "
                "regions. The models look at all 55 together."),
    ("Malware score", "The Random Forest model's confidence (0-100%) that the snapshot is malicious."),
    ("Zero-day anomaly", "A second model (Isolation Forest) that flags memory that looks unlike anything it was "
                         "trained on — useful for new, unknown threats."),
    ("SHAP", "Explains the verdict by showing how much each feature pushed the score towards malware or benign."),
    ("LIME", "An independent second explanation: simple rules learned around this one snapshot."),
    ("Hash (SHA-256 / MD5)", "A fingerprint of a file. Change one byte and the fingerprint changes completely, so "
                             "matching hashes prove a file is unchanged."),
    ("Chain of custody", "The record of who handled the evidence, when, and proof it was not altered. Here every "
                         "step re-checks the hash and is written to a tamper-evident ledger."),
    ("Provenance", "Where the evidence came from (device, owner, collector, time, tool) and who it is prepared for."),
    ("Audit log", "A tamper-evident record of every sign-in, account change and analysis. Each line is linked to "
                  "the previous one, so edits are detected."),
]

FAQ = [
    ("Why was I signed out?",
     f"Sessions end after {auth.IDLE_TIMEOUT_MIN} minutes without activity, when you reload the browser page, or "
     "when an administrator disables your account. Use the top menu to move between pages — it keeps you signed in."),
    ("Why is analysis blocked?",
     "Either a hash check failed (the evidence changed after it was acquired), the hash you entered from the "
     "acquisition tool does not match, or the file failed input validation. The red message on the page says which."),
    ("How do I prove a report was not changed?",
     "Each PDF has a SHA-256 recorded in the custody ledger, the audit log and a .sha256 file. Run "
     "`certutil -hashfile report.pdf SHA256` (Windows) or `sha256sum report.pdf` and compare."),
    ("My memory dump is very large.",
     "Choose **Memory dump** and paste its path on this computer instead of uploading it. It is analysed in place "
     "and never copied."),
    ("I forgot my password / my account is locked.",
     f"Accounts unlock automatically after {auth.LOCKOUT_MINUTES} minutes. An administrator can also unlock it or "
     "set a temporary password on the **Users** page."),
    ("Can I continue a case later?",
     "Yes. Open **Cases**, pick the case and press **Continue this case**. A new session is recorded for it."),
]


def render_help_page():
    ui.section("Help & guide", "Everything you need to analyse memory evidence with confidence.", "help")

    st.markdown("##### Analyse evidence in five steps")
    ui.guide_steps([
        ("folder_open", "Open a case", "Enter a case number and who the findings are prepared for."),
        ("travel_explore", "Record the origin", "Where the evidence came from, who collected it, when and how."),
        ("upload_file", "Load evidence", "A sample profile, a Volatility CSV or a raw Windows memory dump."),
        ("troubleshoot", "Analyse", "Pick a snapshot and press Analyse — you get a verdict and its reasons."),
        ("picture_as_pdf", "Share the report", "Download the sealed PDF. Every step is hash-verified."),
    ])

    st.markdown("##### Reading the verdict")
    ui.kpi_row([
        ui.kpi("Normal", f"{ui.icon('verified_user')} below 40%", "Matches a healthy Windows system", color=ui.GOOD),
        ui.kpi("Suspicious", f"{ui.icon('warning')} 40 – 75%", "Review before releasing the host", color=ui.WARNING),
        ui.kpi("High risk", f"{ui.icon('gpp_bad')} 75% and above", "Isolate the host and escalate", color=ui.CRITICAL),
    ])
    st.caption("The score is a model's confidence, not proof. Always read the explanation and confirm with an "
               "analyst before taking action.")

    c_terms, c_faq = st.columns([1, 1], gap="large")
    with c_terms:
        st.markdown("##### Glossary")
        for term, meaning in GLOSSARY:
            with st.expander(term):
                st.write(meaning)
    with c_faq:
        st.markdown("##### Frequently asked questions")
        for question, answer in FAQ:
            with st.expander(question):
                st.markdown(answer)
