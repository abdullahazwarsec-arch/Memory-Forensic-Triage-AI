"""
Offline Help Assistant
======================
A floating "Ask the assistant" chat on every page after sign-in. It runs
entirely on this machine - no AI service, no network, no API key.

How it answers
* Questions are matched to topics by blending a character n-gram TF-IDF
  model (tolerant of typos) with a word-level one (so a question must share
  real words with a topic, not just letter fragments).
* Topics come from the Help page glossary/FAQ plus "how do I..." guides.
* Context topics ("explain my result", "what next?", "is the evidence
  intact?") answer from a summary of the dashboard state supplied by app.py:
  risk level, score, top explaining features, integrity and progress. By
  design it never receives hashes, file names, provenance or raw evidence.
* Administration topics are role-aware.

Every question is recorded in the audit log (topic, match score and the first
120 characters of the question).
"""

import re
import logging
import functools

import streamlit as st
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from . import auth
from . import help_page
from . import ui_theme as ui


MATCH_THRESHOLD = 0.30
CHAR_WEIGHT, WORD_WEIGHT = 0.65, 0.35
_log = logging.getLogger("triage.assistant")

SYNONYMS = {
    r"\blog ?in\b": "sign in", r"\blog ?out\b": "sign out", r"\blogged out\b": "signed out",
    r"\bpdf\b": "pdf report", r"\bdump\b": "memory dump", r"\bram\b": "memory",
    r"\bverdict\b": "result verdict", r"\btampered\b": "modified tampered", r"\bpwd\b": "password",
}


# ── Context-aware answers ────────────────────────────────────────────────────
def _explain_result(ctx: dict) -> str:
    r = ctx.get("result")
    if not r:
        return ("There is no result yet. Open a case, load evidence and press **Analyse snapshot** — then ask me "
                "again and I will explain the verdict in plain words.")
    lines = [f"**{r['risk'].title()}** — the model is **{r['score']:.1f}%** confident this memory snapshot is "
             f"{'malicious' if r['malware'] else 'benign'}."]
    if r["drivers"]:
        lines.append("\nThe biggest reasons:")
        for name, toward_malware, pts in r["drivers"]:
            lines.append(f"- **{name}** pushed the score {'towards malware' if toward_malware else 'towards benign'} "
                         f"({pts:+.1f} pts)")
    if r["anomaly"]:
        lines.append("\nThe zero-day detector also flagged this memory as **unusual** compared with known samples.")
    lines.append("\nThe **Explainability** tab shows every reason with a chart. Remember: the score is a model's "
                 "confidence, not proof — confirm before acting.")
    return "\n".join(lines)


def _next_step(ctx: dict) -> str:
    if not ctx.get("case_open"):
        return ("**Next: open a case.** On the **Triage** page enter a case number and who the findings are "
                "prepared for, then press **Open case session**.")
    if not ctx.get("evidence_loaded"):
        return ("**Next: load the evidence.** Fill in the **Evidence origin** (where it came from, who collected "
                "it), then choose a sample, upload a Volatility CSV or add a memory dump.")
    if ctx.get("integrity_ok") is False:
        return ("**Stop — the evidence failed an integrity check.** Do not rely on any result. Open the **Chain of "
                "custody** tab to see which step failed and re-acquire the evidence from the original source.")
    if ctx.get("validation") == "block":
        return "**The evidence failed input validation**, so it cannot be analysed. Check the red message for why."
    if ctx.get("validation") == "warn" and not ctx.get("result"):
        return ("**Review the validation warning**, tick the acknowledgement box if you accept it, then press "
                "**Analyse snapshot**.")
    r = ctx.get("result")
    if not r:
        return "**Next: pick a memory snapshot (row) and press Analyse snapshot.**"
    actions = "\n".join(f"- {re.sub(r'^[^A-Za-z]+', '', a)}" for a in r["actions"])
    report = ("Download the sealed PDF from the **Report** tab." if ctx.get("report_ready")
              else "Then open the **Report** tab to generate the sealed PDF.")
    return f"For a **{r['risk'].title()}** result the recommended response is:\n{actions}\n\n{report}"


def _integrity(ctx: dict) -> str:
    if not ctx.get("evidence_loaded"):
        return "No evidence is loaded yet, so there is nothing to verify."
    if ctx.get("integrity_ok"):
        return (f"**Yes — the evidence is intact.** All {ctx.get('checkpoints', 0)} custody checkpoints match the "
                "fingerprint taken when it arrived, and the ledger links are unbroken.")
    return ("**No — an integrity check failed.** A fingerprint taken later does not match the original, so the "
            "evidence may have changed. Analysis is blocked; see the **Chain of custody** tab.")


def _status(ctx: dict) -> str:
    steps = [("Case opened", ctx.get("case_open")), ("Evidence loaded", ctx.get("evidence_loaded")),
             ("Integrity verified", ctx.get("integrity_ok")), ("Analysis done", bool(ctx.get("result"))),
             ("Report sealed", ctx.get("report_ready"))]
    done = "\n".join(f"- {'✅' if ok else '⬜'} {label}" for label, ok in steps)
    return f"Here is where you are:\n{done}\n\nAsk **“what should I do next?”** for the next action."


def _audit(ctx: dict) -> str:
    if ctx.get("role") == "admin":
        return ("Open **Audit log** in the top menu. **Sign-ins & sign-outs** lists every sign-in, failed attempt, "
                "lockout and sign-out with time and session length; filter by user, event or date and export to "
                "CSV. The green banner confirms the log has not been altered.")
    return ("The full audit log is for administrators. You can see **your own** recent sign-in activity on "
            "**My account**.")


def _users(ctx: dict) -> str:
    if ctx.get("role") == "admin":
        return ("Open **Users** in the top menu. **Create user** adds an account with a temporary password (they "
                "choose their own at first sign-in). **Manage user** lets you disable/enable, unlock, change the "
                "role or reset the password. Every change is recorded in the audit log.")
    return "Accounts are managed by an administrator — please ask your lab administrator."


def _greeting(ctx: dict) -> str:
    return (f"Hi {ctx.get('name', '').split(' ')[0] or 'there'}! I can explain your result, tell you what to do "
            "next, and answer questions about the dashboard and forensic terms. I run **offline** — nothing you "
            "type leaves this computer.")


# ── Topics ───────────────────────────────────────────────────────────────────
TOPICS = [
    ("explain_result", ["explain my result", "why is it malware", "why is it suspicious", "explain the verdict",
                        "what does my result mean", "why high risk", "why is it benign", "what caused this score",
                        "why did it flag this", "summarise the analysis"], _explain_result),
    ("next_step", ["what should i do next", "next step", "what now", "recommended action", "what do i do",
                   "how should i respond", "what action should i take", "now what"], _next_step),
    ("integrity", ["is the evidence intact", "was the evidence tampered", "integrity status",
                   "has the file been modified", "chain of custody status", "can i trust this evidence"], _integrity),
    ("status", ["where am i", "what is my progress", "status", "which step am i on", "what have i done"], _status),
    ("open_case", ["how do i open a case", "start a case", "create a case", "new case", "case number",
                   "how to begin", "get started"],
     "On **Triage**, enter a **case number** (one is suggested), the **recipient** the findings are for, the purpose "
     "and an optional reference, then press **Open case session**. Everything you do afterwards is recorded under "
     "that case and your account."),
    ("recipient", ["who is the evidence prepared for", "what is the recipient field", "who is the recipient",
                   "prepared for",
                   "purpose field", "reference number"],
     "**Prepared for** records who will receive the findings — e.g. an investigating officer, a client or a court — "
     "with the purpose and a reference number. It is sealed in the custody ledger and printed on the PDF report."),
    ("origin", ["record the evidence origin", "where did the evidence come from", "evidence origin form",
                "custodian", "collected by", "source device"],
     "Before loading evidence, fill in **Evidence origin**: the source device/host, its owner or custodian, where "
     "and when it was collected, who collected it and with which tool. These are sealed into the custody ledger "
     "when the evidence arrives, so enter them first."),
    ("acq_hash", ["acquisition tool hash", "hash from dumpit", "hash from ftk imager", "reported hash",
                  "hash mismatch at acquisition", "compare tool hash"],
     "In **Evidence origin** you can paste the SHA-256 or MD5 printed by the acquisition tool (DumpIt, FTK "
     "Imager…). When the evidence arrives the dashboard computes its own hash and compares them. **A mismatch "
     "blocks analysis** — it means the file you loaded is not the one that was acquired. Enter it *before* "
     "loading the evidence."),
    ("load_csv", ["how do i upload a csv", "load volatility csv", "upload features file", "import csv",
                  "csv file"],
     "Choose **Volatility CSV** under *Evidence source* and drop the file. It must contain the 55 Volatility memory "
     "features (one row per snapshot) and be under 50 MB. It is fingerprinted on arrival and stored as a "
     "write-protected copy."),
    ("load_dump", ["how do i analyse a memory dump", "how do i load a memory dump", "upload raw memory image",
                   "memory dump is too large to upload", "load a large memory dump", "memory image path",
                   "vmem file", "raw file", "dmp file", "analyse a ram image"],
     "Choose **Memory dump**. Upload the image, or for large files paste its **path on this computer** — it is "
     "then analysed in place and never copied. Volatility 3 extracts the 55 features (a few minutes); the image is "
     "hashed before and after to prove it was not changed. Windows images only."),
    ("samples", ["try a sample", "demo data", "sample profile", "test the dashboard", "example data"],
     "Choose **Sample profile** under *Evidence source* and pick one (e.g. *Active ransomware*). Samples are "
     "reference profiles from the CIC-MalMem2022 research dataset — ideal for learning the dashboard."),
    ("analyse", ["how do i analyse", "run analysis", "analyse snapshot", "what is a snapshot row",
                 "run the model", "start analysis"],
     "Pick a **memory snapshot** (a row of the file) and press **Analyse snapshot**. The dashboard first re-checks "
     "the evidence fingerprints, then runs the Random Forest and the zero-day detector and explains the verdict."),
    ("scan_all", ["scan all rows", "analyse every row", "batch scan", "check all snapshots",
                  "scan every snapshot at once", "score all rows together"],
     "**Scan all rows** quickly scores every snapshot in the file and lists them by risk, so you can choose the "
     "riskiest one to analyse in detail."),
    ("report", ["download the report", "pdf report", "export report", "generate report", "print report"],
     "After an analysis open the **Report** tab and press **Download**. The PDF includes the verdict, explanations, "
     "provenance and the full custody ledger, and its SHA-256 is recorded so any later change can be detected. "
     "Older reports are on the **Cases** page."),
    ("validation", ["input validation warning", "missing features", "why acknowledge", "validation blocked",
                    "negative values", "empty values"],
     "**Input validation** checks the 55 features the model needs. Missing or empty values are treated as 0 — you "
     "must tick the acknowledgement to continue because the verdict may be less reliable. Infinite or negative "
     "values, or more than 20% unusable features, **block** analysis."),
    ("cases_page", ["find an old case", "continue a case", "previous cases", "cases page",
                    "download an old report", "case history"],
     "Open **Cases** in the top menu. Search any case, see who it was prepared for, re-verify each evidence item, "
     "download its sealed reports, and press **Continue this case** to work on it again."),
    ("audit_log", ["audit log", "who signed in", "login history", "sign in activity", "failed logins",
                   "who logged in"], _audit),
    ("users_admin", ["create a user", "add an analyst", "reset someone's password", "disable an account",
                     "unlock a user", "manage users", "new account"], _users),
    ("change_password", ["change my password", "update password", "new password", "set password"],
     f"Open **My account** and use **Change password**. Passwords need at least {auth.MIN_PASSWORD_LEN} characters "
     "with letters and digits, and must not contain your username."),
    ("sign_out", ["how do i sign out", "sign out", "exit the dashboard", "end session"],
     "Press **Sign out** in the sidebar. Any open case session is closed and your sign-out is recorded."),
    ("risk_levels", ["risk levels", "what does suspicious mean", "score thresholds", "what does high risk mean",
                     "what is normal", "risk score meaning"],
     "**Normal** — below 40%, matches a healthy system.\n\n**Suspicious** — 40–75%, needs analyst review before "
     "releasing the host.\n\n**High risk** — 75% and above, isolate the host and escalate."),
    ("explain_charts", ["how to read the chart", "red and blue bars", "shap vs lime", "explainability tab",
                        "what do the bars mean"],
     "In the **Explainability** charts, **red bars push towards malware** and **blue bars towards benign**; longer "
     "bars matter more. SHAP shows each feature's contribution; LIME is an independent second opinion. If both "
     "agree on the top reasons, the explanation is more trustworthy."),
    ("privacy", ["is my data sent anywhere", "are you an ai", "is this chatbot online", "privacy",
                 "do you use chatgpt", "where do answers come from"],
     "I run **entirely offline** on this computer — no AI service, nothing you type leaves the machine. I answer "
     "from the built-in guide and a summary of your current result (no hashes, file names or personal details)."),
    ("greeting", ["hi", "hello", "hey", "good morning", "help", "what can you do", "who are you"], _greeting),
    ("thanks", ["thanks", "thank you", "great", "ok thanks", "cheers"],
     "You're welcome! Ask me anything else about the dashboard or your result."),
]

# Other names people use for glossary terms
ALIASES = {
    "zero-day anomaly": ["isolation forest", "anomaly detection", "unknown threat detector", "zero day"],
    "malware score": ["random forest", "confidence score", "probability of malware"],
    "hash (sha-256 / md5)": ["sha256", "md5", "fingerprint", "checksum", "hash"],
    "memory dump": ["memory image", "ram capture", "raw image"],
    "volatility": ["volatility 3", "volatility framework"],
    "feature": ["features", "memory features", "the 55 features"],
    "chain of custody": ["custody", "custody ledger"],
}
for _term, _meaning in help_page.GLOSSARY:
    _key = _term.lower()
    _names = [_key] + ALIASES.get(_key, [])
    TOPICS.append((f"term:{_key}", [p for n in _names for p in (f"what is {n}", f"explain {n}", n)]
                   + [f"meaning of {_key}", f"what does {_key} mean"], f"**{_term}** — {_meaning}"))
for _q, _a in help_page.FAQ:
    TOPICS.append((f"faq:{_q}", [_q.lower().rstrip("?.")], _a))

SUGGESTIONS = {
    "start":    ["How do I open a case?", "What is a memory dump?", "Try a sample", "What can you do?"],
    "evidence": ["What should I do next?", "Is the evidence intact?", "How do I analyse?", "Scan all rows"],
    "result":   ["Explain my result", "What should I do next?", "How do I download the report?",
                 "How to read the chart"],
}


def _normalise(text: str) -> str:
    text = text.lower()
    for pattern, repl in SYNONYMS.items():
        text = re.sub(pattern, repl, text)
    return re.sub(r"[^a-z0-9%\s]", " ", text)


@functools.lru_cache(maxsize=1)
def _model():
    examples, owners = [], []
    for i, (_, phrases, _) in enumerate(TOPICS):
        for phrase in phrases:
            examples.append(_normalise(phrase))
            owners.append(i)
    chars = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
    words = TfidfVectorizer(analyzer="word", stop_words="english", token_pattern=r"[a-z0-9%]{2,}")
    return (chars, chars.fit_transform(examples)), (words, words.fit_transform(examples)), owners


def match(question: str):
    """Best topic for a question: (topic_index or None, score, top-3 topic indices)."""
    (chars, c_matrix), (words, w_matrix), owners = _model()
    q = _normalise(question)
    sims = (CHAR_WEIGHT * cosine_similarity(chars.transform([q]), c_matrix)[0]
            + WORD_WEIGHT * cosine_similarity(words.transform([q]), w_matrix)[0])
    best = {}
    for sim, owner in zip(sims, owners):
        best[owner] = max(best.get(owner, 0.0), float(sim))
    ranked = sorted(best, key=best.get, reverse=True)
    top = ranked[0]
    return (top if best[top] >= MATCH_THRESHOLD else None), best[top], ranked[:3]


def answer(question: str, ctx: dict):
    """Returns (markdown answer, topic id, score)."""
    idx, score, near = match(question)
    if idx is None:
        options = ", ".join(f"“{TOPICS[i][1][0]}”" for i in near)
        return (f"I'm not sure I understood. Did you mean {options}? You can also open **Help** in the top menu "
                "for the full guide."), "unknown", score
    topic_id, _, reply = TOPICS[idx]
    return (reply(ctx) if callable(reply) else reply), topic_id, score


def _suggestions(ctx: dict) -> list:
    if ctx.get("result"):
        return SUGGESTIONS["result"]
    return SUGGESTIONS["evidence"] if ctx.get("case_open") else SUGGESTIONS["start"]


# ── UI ───────────────────────────────────────────────────────────────────────
def render(ctx: dict):
    """Floating assistant (bottom-right) with chat history, suggestions and an input box."""
    history = st.session_state.setdefault("assistant_history", [])
    with st.container(key="assistant_fab"):
        with st.popover("Assistant", icon=":material/support_agent:"):
            ui.render_html(f'<div class="fx-asst-head">{ui.mac_icon("support_agent", 36)}<div>'
                           '<div class="fx-asst-title">HazMem assistant</div>'
                           '<div class="fx-asst-sub">Offline · answers from the guide and your current result'
                           '</div></div></div>')
            log_box = st.container(height=230, border=False)
            picked = st.pills("Suggestions", _suggestions(ctx), key=f"asst_pick_{len(history)}",
                              label_visibility="collapsed")
            typed = st.chat_input("Ask about the dashboard or your result…", key="assistant_input")
            question = (typed or picked or "").strip()
            if question:
                reply, topic, score = answer(question[:500], ctx)
                history += [("user", question), ("assistant", reply)]
                del history[:-40]
                _log.info(f"ASSISTANT | USER={ctx.get('username', '-')} | TOPIC={topic} | SCORE={score:.2f} | "
                          f"Q={re.sub(r'[|=]', '/', question)[:120]}")
            with log_box:
                if not history:
                    with st.chat_message("assistant", avatar=":material/support_agent:"):
                        st.markdown(_greeting(ctx))
                for role, text in history:
                    with st.chat_message(role, avatar=":material/support_agent:" if role == "assistant"
                                         else ":material/person:"):
                        st.markdown(text)
            if history and st.button("Clear chat", icon=":material/delete_sweep:", key="asst_clear"):
                history.clear()
                st.rerun()
