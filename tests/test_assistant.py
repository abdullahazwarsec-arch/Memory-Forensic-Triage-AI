"""Offline help assistant: topic matching, refusal of off-topic questions, context answers."""
import pytest

from hazmem import assistant

CASES = [
    ("why did it say malware?", "explain_result"),
    ("can you explain the result in simple words", "explain_result"),
    ("what should I do now", "next_step"),
    ("wat do i do next", "next_step"),
    ("has the evidence been tampered with", "integrity"),
    ("how to start a new case", "open_case"),
    ("how can I upload my csv file", "load_csv"),
    ("my memory dump is 16GB how do i load it", "load_dump"),
    ("is there demo data to try", "samples"),
    ("how do i get the pdf", "report"),
    ("how do i prove the report wasnt changed", "faq:How do I prove a report was not changed?"),
    ("what is SHAP", "term:shap"),
    ("whats a hash", "term:hash (sha-256 / md5)"),
    ("meaning of chain of custody", "term:chain of custody"),
    ("explain lime", "term:lime"),
    ("what is isolation forest", "term:zero-day anomaly"),
    ("what is a feature", "term:feature"),
    ("what does suspicious mean", "risk_levels"),
    ("what does the risk score mean", "risk_levels"),
    ("why was I logged out", "faq:Why was I signed out?"),
    ("i forgot my password", "faq:I forgot my password / my account is locked."),
    ("how do I change my password", "change_password"),
    ("who logged in today", "audit_log"),
    ("add a new analyst account", "users_admin"),
    ("what do the red bars mean", "explain_charts"),
    ("is my data sent to chatgpt", "privacy"),
    ("hello", "greeting"),
    ("thank you!", "thanks"),
    ("where can I find old cases", "cases_page"),
    ("the tool hash from dumpit", "acq_hash"),
    ("why missing features warning", "validation"),
    ("how to analyze", "analyse"),
    ("scan every snapshot at once", "scan_all"),
    ("whos the reciepent", "recipient"),
    ("how do i log out", "sign_out"),
    ("whats the weather in london", "unknown"),
    ("best pizza recipe", "unknown"),
    ("who won the football match", "unknown"),
    ("write me a poem", "unknown"),
]

RESULT_CTX = {
    "role": "analyst", "name": "Jane", "case_open": True, "evidence_loaded": True, "integrity_ok": True,
    "checkpoints": 7, "validation": "ok", "report_ready": False,
    "result": {"risk": "SUSPICIOUS", "score": 74.4, "malware": True, "anomaly": True,
               "drivers": [("Shared Service Host Processes", True, 12.3), ("Loaded DLLs", False, -4.1)],
               "actions": ["🟡 Do NOT take automated action — human review required"]},
}


@pytest.mark.parametrize("question,expected", CASES)
def test_question_matches_topic(question, expected):
    _, topic, _ = assistant.answer(question, {"role": "analyst", "name": "Jane"})
    assert topic == expected


def test_explains_the_current_result_without_sensitive_data():
    text = assistant.answer("explain my result", RESULT_CTX)[0]
    assert "74.4%" in text and "Shared Service Host Processes" in text and "unusual" in text


def test_next_step_follows_progress():
    assert "open a case" in assistant.answer("what next", {"case_open": False})[0].lower()
    assert "human review" in assistant.answer("what next", RESULT_CTX)[0]
    blocked = dict(RESULT_CTX, integrity_ok=False, result=None)
    assert "integrity" in assistant.answer("what next", blocked)[0].lower()


def test_admin_topics_are_role_aware():
    assert "administrator" in assistant.answer("create a user", {"role": "analyst"})[0]
    assert "Users" in assistant.answer("create a user", {"role": "admin"})[0]
