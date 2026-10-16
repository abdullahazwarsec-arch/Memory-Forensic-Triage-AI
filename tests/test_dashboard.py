"""
End-to-end dashboard tests (Streamlit AppTest, no browser): first-run setup,
sign-in, lockout, sessions, roles, account-store sealing and a full triage run.
"""
import json
import os
import time

import pytest
from streamlit.testing.v1 import AppTest

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


def texts(at) -> str:
    return " ".join(str(x.value) for kind in (at.markdown, at.error, at.info, at.warning, at.success) for x in kind)


def button(at, label):
    return next(b for b in at.button if b.label == label)


def field(at, label):
    return next(t for t in at.text_input if t.label == label)


def run_app() -> AppTest:
    return AppTest.from_file(APP, default_timeout=180).run()


def sign_in(at, username, password):
    field(at, "Username").set_value(username)
    field(at, "Password").set_value(password)
    button(at, "Sign in").click().run()
    return at


def test_first_run_creates_administrator(fresh_users):
    auth = fresh_users
    at = run_app()
    assert "Create the first administrator" in texts(at)
    for label, value in [("Username", "admin1"), ("Full name", "Alice Admin"),
                         ("Password", "weak"), ("Repeat password", "weak")]:
        field(at, label).set_value(value)
    button(at, "Create administrator").click().run()
    assert "Password needs" in texts(at) and not auth.has_users()
    field(at, "Password").set_value("Str0ngPassw0rd")
    field(at, "Repeat password").set_value("Str0ngPassw0rd")
    button(at, "Create administrator").click().run()
    assert auth.has_users()
    stored = open(auth.USERS_PATH, encoding="utf-8").read()
    assert "Str0ngPassw0rd" not in stored and "pbkdf2_sha256$600000$" in stored


def test_sign_in_out_and_case_attribution(fresh_users):
    fresh_users.create_user("admin1", "Alice Admin", "admin", "Str0ngPassw0rd", "test", must_change_password=False)
    at = sign_in(run_app(), "admin1", "wrongpassword1")
    assert "Invalid username or password" in texts(at)
    sign_in(at, "admin1", "Str0ngPassw0rd")
    assert not at.exception and "Start a case" in texts(at)
    analyst = field(at, "Analyst (signed-in account)")
    assert analyst.value == "Alice Admin (admin1)" and analyst.disabled
    button(at, "Sign out").click().run()
    assert "You have been signed out" in texts(at)


def test_forced_password_change_and_revocation(fresh_users):
    auth = fresh_users
    auth.create_user("admin1", "Alice Admin", "admin", "Str0ngPassw0rd", "test", must_change_password=False)
    auth.create_user("bob", "Bob Analyst", "analyst", "TempPassw0rd1", created_by="admin1")
    at = sign_in(run_app(), "bob", "TempPassw0rd1")
    assert "must set a new password" in texts(at)
    field(at, "Current password").set_value("TempPassw0rd1")
    field(at, "New password").set_value("Analyst2026Pass")
    field(at, "Repeat new password").set_value("Analyst2026Pass")
    button(at, "Change password").click().run()
    assert "Start a case" in texts(at) and at.session_state["auth_user"]["role"] == "analyst"
    auth.set_active("bob", False, by="admin1")
    at.run()
    assert "account was disabled" in texts(at)


def test_idle_timeout_and_lockout(fresh_users):
    auth = fresh_users
    auth.create_user("bob", "Bob Analyst", "analyst", "Analyst2026Pass", "test", must_change_password=False)
    at = sign_in(run_app(), "bob", "Analyst2026Pass")
    at.session_state["auth"]["last_seen"] = time.time() - 31 * 60
    at.run()
    assert "inactivity" in texts(at)
    for _ in range(5):
        sign_in(at, "bob", "nope-wrong-1")
    sign_in(at, "bob", "Analyst2026Pass")
    assert "Invalid username" in texts(at) and auth.get_user("bob")["locked"]


def test_admin_self_protection(fresh_users):
    auth = fresh_users
    auth.create_user("admin1", "Alice Admin", "admin", "Str0ngPassw0rd", "test", must_change_password=False)
    with pytest.raises(auth.AuthError):
        auth.set_active("admin1", False, by="admin1")
    with pytest.raises(auth.AuthError):
        auth.set_role("admin1", "analyst", by="admin1")


def test_hand_edited_account_store_blocks_sign_in(fresh_users):
    auth = fresh_users
    auth.create_user("bob", "Bob Analyst", "analyst", "Analyst2026Pass", "test")
    data = json.load(open(auth.USERS_PATH))
    data["users"]["bob"]["role"] = "admin"
    json.dump(data, open(auth.USERS_PATH, "w"))
    assert "Account store integrity failure" in texts(run_app())


def test_full_triage_run_seals_report(fresh_users):
    fresh_users.create_user("admin1", "Alice Admin", "admin", "Str0ngPassw0rd", "test", must_change_password=False)
    at = sign_in(run_app(), "admin1", "Str0ngPassw0rd")
    field(at, "Recipient *").set_value("DCI Test Recipient")
    button(at, "Start case").click().run()
    assert "Evidence checked" in texts(at)
    button(at, "Analyse evidence").click().run()
    assert not at.exception
    result = at.session_state["current_triage"]
    assert result["risk"] in ("NORMAL", "SUSPICIOUS", "HIGH RISK")
    evidence = at.session_state["evidence"]
    chain = evidence["chain"]
    stages = [e["stage"] for e in chain.events]
    assert chain.is_intact and "Provenance" in stages and "Report" in stages
    assert chain.provenance["prepared_for"]["name"] == "DCI Test Recipient"


def test_appearance_preference_is_saved(fresh_users):
    auth = fresh_users
    auth.create_user("bob", "Bob Analyst", "analyst", "Analyst2026Pass", "test", must_change_password=False)
    auth.set_preference("bob", "theme", "light")
    assert auth.get_user("bob")["preferences"]["theme"] == "light"
    with pytest.raises(auth.AuthError):
        auth.set_preference("bob", "theme", "neon")
    at = sign_in(run_app(), "bob", "Analyst2026Pass")
    assert at.session_state["appearance"] == "light"


def test_simple_view_by_default_and_technical_switch(fresh_users):
    auth = fresh_users
    auth.create_user("bob", "Bob Analyst", "analyst", "Analyst2026Pass", "test", must_change_password=False)
    at = sign_in(run_app(), "bob", "Analyst2026Pass")
    assert at.session_state["expert_mode"] is False
    field(at, "Recipient *").set_value("Test Recipient")
    button(at, "Start case").click().run()
    sections = lambda: [e.label for e in list(at.expander) + list(at.status)]   # icon expanders are "status" blocks
    assert "Preview evidence data" not in sections()                                # technical item hidden
    next(t for t in at.toggle if t.label == "Show technical details").set_value(True).run()
    assert "Preview evidence data" in sections()
    assert auth.get_user("bob")["preferences"]["view"] == "expert"
