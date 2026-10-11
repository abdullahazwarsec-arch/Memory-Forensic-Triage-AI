"""
Account & audit pages of the dashboard
======================================
First-run administrator setup, sign-in, the administrator-only Audit Log and
User Management pages, and the My Account page. The signed-in user is read
from st.session_state["auth_user"], which app.py refreshes on every run.
"""

import os
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

import auth
import audit_log
import ui_theme as ui


AUDIT_LOG_PATH = None   # set by app.py

SIGNIN_EVENTS = {
    "LOGIN_SUCCESS":   "✅ Signed in",
    "LOGIN_FAILED":    "❌ Failed sign-in",
    "ACCOUNT_LOCKED":  "🔒 Account locked",
    "LOGOUT":          "🚪 Signed out",
    "SESSION_TIMEOUT": "⏱️ Timed out (idle)",
    "SESSION_REVOKED": "⛔ Session revoked",
}
ACCOUNT_EVENTS = {
    "USER_CREATED":           "➕ User created",
    "PASSWORD_CHANGED":       "🔑 Password changed",
    "PASSWORD_CHANGE_FAILED": "⚠️ Password change failed",
    "PASSWORD_RESET":         "🔁 Password reset",
    "ROLE_CHANGED":           "🎭 Role changed",
    "USER_DISABLED":          "🚫 User disabled",
    "USER_ENABLED":           "✔️ User enabled",
    "USER_UNLOCKED":          "🔓 User unlocked",
}
ROLE_LABELS = {"admin": "Administrator", "analyst": "Analyst"}


def client_ip() -> str:
    try:
        # Streamlit withholds the address for connections from this machine
        return st.context.ip_address or "localhost"
    except Exception:
        return "-"


def local_time(iso_utc: str) -> str:
    if not iso_utc:
        return "never"
    dt = datetime.strptime(iso_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone()
    return dt.strftime("%Y-%m-%d %H:%M")


def _brand_header(subtitle: str):
    ui.page_header("MemTriage", "XAI", subtitle, [ui.pill("Restricted access", "accent")])


# ── First run & sign-in ───────────────────────────────────────────────────────
def render_first_run_setup():
    _brand_header("First-run setup — create the administrator account")
    _, mid, _ = st.columns([1, 1.6, 1])
    with mid, st.container(border=True):
        st.markdown("#### Create the first administrator")
        st.caption("No accounts exist yet. This administrator can then create analyst accounts and read the "
                   f"audit log. Passwords need at least {auth.MIN_PASSWORD_LEN} characters with letters and digits.")
        with st.form("first_admin", border=False):
            username  = st.text_input("Username", placeholder="e.g. admin")
            full_name = st.text_input("Full name", placeholder="Name of the lab administrator")
            password  = st.text_input("Password", type="password")
            confirm   = st.text_input("Repeat password", type="password")
            submitted = st.form_submit_button("Create administrator", type="primary", width="stretch",
                                              icon=":material/admin_panel_settings:")
        if submitted:
            if password != confirm:
                st.error("Passwords do not match.")
            elif auth.has_users():
                st.error("An administrator was already created. Reload the page to sign in.")
            else:
                try:
                    auth.create_user(username, full_name, "admin", password, created_by="first-run setup",
                                     must_change_password=False)
                except auth.AuthError as e:
                    st.error(str(e))
                else:
                    st.session_state["login_notice"] = "Administrator created — sign in to continue."
                    st.rerun()


def render_login():
    """Sign-in form. Returns the authenticated user record, or None."""
    _brand_header("Explainable AI triage for Windows memory forensics")
    _, mid, _ = st.columns([1, 1.3, 1])
    with mid, st.container(border=True):
        st.markdown("#### Sign in")
        notice = st.session_state.pop("login_notice", None)
        if notice:
            st.info(notice, icon=":material/info:")
        with st.form("login", border=False):
            username = st.text_input("Username", autocomplete="username")
            password = st.text_input("Password", type="password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", type="primary", width="stretch", icon=":material/login:")
        st.caption(f"Accounts lock for {auth.LOCKOUT_MINUTES} minutes after {auth.MAX_FAILED} failed attempts. "
                   "All sign-ins are recorded in the audit log.")
        if submitted:
            user = auth.authenticate(username, password, client=client_ip())
            if user:
                return user
            st.error("Invalid username or password, or the account is locked or disabled.",
                     icon=":material/error:")
    return None


def render_password_change(user: dict, forced: bool = False):
    if forced:
        st.warning("You must set a new password before using the dashboard.", icon=":material/key:")
    with st.form("change_password", clear_on_submit=True):
        current = st.text_input("Current password", type="password")
        new     = st.text_input("New password", type="password",
                                help=f"At least {auth.MIN_PASSWORD_LEN} characters, letters and digits.")
        confirm = st.text_input("Repeat new password", type="password")
        submitted = st.form_submit_button("Change password", type="primary", icon=":material/key:")
    if submitted:
        if new != confirm:
            st.error("New passwords do not match.")
            return
        try:
            auth.change_password(user["username"], current, new)
        except auth.AuthError as e:
            st.error(str(e))
        else:
            st.toast("Password changed", icon="🔑")
            st.rerun()


# ── Audit log data ────────────────────────────────────────────────────────────
@st.cache_data(ttl=5, show_spinner=False)
def _audit_frame(path: str, mtime: float):  # mtime is part of the cache key
    check = audit_log.verify_log(path)
    rows = []
    for e in audit_log.read_entries(path, check["bad_lines"]):
        f = e["fields"]
        rows.append({
            "Line": e["line"],
            "Time": pd.to_datetime(e["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce"),
            "Level": e["level"],
            "Category": e["category"],
            "Event": f.get("EVENT", ""),
            "User": f.get("USER", ""),
            "Client": f.get("CLIENT", ""),
            "Details": " · ".join(f"{k.lower()}: {v}" for k, v in f.items()
                                  if k not in ("EVENT", "USER", "CLIENT")),
            "Message": e["message"],
            "Chain": e["chain"],
        })
    return pd.DataFrame(rows), check


def load_audit():
    if not AUDIT_LOG_PATH or not os.path.isfile(AUDIT_LOG_PATH):
        return pd.DataFrame(), None
    return _audit_frame(AUDIT_LOG_PATH, os.path.getmtime(AUDIT_LOG_PATH))


CHAIN_LABELS = {"ok": "🟢 Verified", "legacy": "⚪ Pre-chain (anchored)", "broken": "🔴 TAMPERED"}


def _event_table(df: pd.DataFrame, labels: dict, key: str, height: int = 460):
    view = df.assign(Event=df["Event"].map(labels).fillna(df["Event"]),
                     Chain=df["Chain"].map(CHAIN_LABELS)).sort_values("Line", ascending=False)
    st.dataframe(
        view[["Time", "Event", "User", "Client", "Details", "Chain"]],
        hide_index=True, width="stretch", height=height,
        column_config={
            "Time":    st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss", width=170),
            "Event":   st.column_config.TextColumn(width=190),
            "User":    st.column_config.TextColumn(width=130),
            "Client":  st.column_config.TextColumn(width=110),
            "Details": st.column_config.TextColumn(width="large"),
            "Chain":   st.column_config.TextColumn("Integrity", width=170),
        },
    )
    st.download_button("Download CSV", view.drop(columns=["Message"]).to_csv(index=False).encode("utf-8"),
                       file_name=f"{key}_{datetime.now():%Y%m%d_%H%M%S}.csv", mime="text/csv",
                       icon=":material/download:", key=f"dl_{key}")


def _date_filter(df: pd.DataFrame, key: str) -> pd.DataFrame:
    if df.empty or df["Time"].isna().all():
        return df
    first, last = df["Time"].min().date(), df["Time"].max().date()
    picked = st.date_input("Date range", value=(max(first, last - timedelta(days=30)), last),
                           min_value=first, max_value=last, key=f"dates_{key}")
    if isinstance(picked, (tuple, list)) and len(picked) == 2:
        start, end = pd.Timestamp(picked[0]), pd.Timestamp(picked[1]) + pd.Timedelta(days=1)
        df = df[(df["Time"] >= start) & (df["Time"] < end)]
    return df


# ── Pages ─────────────────────────────────────────────────────────────────────
def render_audit_page():
    ui.section("Audit log", "Sign-ins, sign-outs, account administration and every recorded triage event.", "policy")
    df, check = load_audit()
    if check is None or df.empty:
        ui.empty_state("receipt_long", "No audit records yet", "Events appear here as soon as anyone signs in.")
        return

    if check["verified"]:
        st.success(f"**Audit log integrity verified** — {check['chained_lines']:,} HMAC-chained entries intact; "
                   f"{check['legacy_lines']:,} earlier entries anchored by the genesis hash.",
                   icon=":material/verified_user:")
    else:
        st.error("**Audit log integrity check FAILED** — " + "; ".join(check["problems"][:4]),
                 icon=":material/gpp_bad:")

    auth_df = df[df["Category"] == "AUTH"]
    signins = auth_df[auth_df["Event"].isin(SIGNIN_EVENTS)]
    recent  = signins[signins["Time"] >= pd.Timestamp.now() - pd.Timedelta(hours=24)]
    count   = lambda ev: int((recent["Event"] == ev).sum())
    users   = auth.list_users()
    ui.kpi_row([
        ui.kpi("Sign-ins · 24 h", f"{count('LOGIN_SUCCESS'):,}"),
        ui.kpi("Failed sign-ins · 24 h", f"{count('LOGIN_FAILED'):,}",
               color=ui.CRITICAL if count("LOGIN_FAILED") else None),
        ui.kpi("Lockouts · 24 h", f"{count('ACCOUNT_LOCKED'):,}",
               color=ui.WARNING if count("ACCOUNT_LOCKED") else None),
        ui.kpi("Sign-outs · 24 h", f"{count('LOGOUT') + count('SESSION_TIMEOUT') + count('SESSION_REVOKED'):,}"),
        ui.kpi("Accounts", f"{len(users)}", f"{sum(u['locked'] for u in users)} locked · "
                                            f"{sum(not u['active'] for u in users)} disabled"),
    ])
    st.write("")

    t_sign, t_admin, t_all = st.tabs(["Sign-ins & sign-outs", "Account administration", "All audit events"])
    with t_sign:
        c1, c2, c3 = st.columns([1.2, 1.6, 1.3])
        with c1:
            who = st.multiselect("User", sorted(u for u in signins["User"].unique() if u), key="f_user")
        with c2:
            what = st.multiselect("Event", list(SIGNIN_EVENTS), format_func=SIGNIN_EVENTS.get, key="f_event")
        with c3:
            view = _date_filter(signins, "signin")
        if who:
            view = view[view["User"].isin(who)]
        if what:
            view = view[view["Event"].isin(what)]
        st.caption(f"{len(view):,} of {len(signins):,} sign-in events")
        _event_table(view, SIGNIN_EVENTS, "signin_audit")
    with t_admin:
        admin_df = auth_df[auth_df["Event"].isin(ACCOUNT_EVENTS)]
        st.caption(f"{len(admin_df):,} account administration events")
        _event_table(admin_df, ACCOUNT_EVENTS, "account_audit", height=380)
    with t_all:
        c1, c2, c3 = st.columns([1.5, 1, 1.5])
        with c1:
            cats = st.multiselect("Category", sorted(c for c in df["Category"].unique() if c), key="f_cat")
        with c2:
            levels = st.multiselect("Level", ["INFO", "WARNING", "ERROR"], key="f_level")
        with c3:
            text = st.text_input("Search", placeholder="case number, user, hash…", key="f_text")
        view = df
        if cats:
            view = view[view["Category"].isin(cats)]
        if levels:
            view = view[view["Level"].isin(levels)]
        if text:
            view = view[view["Message"].str.contains(text, case=False, regex=False)]
        view = view.assign(Chain=view["Chain"].map(CHAIN_LABELS)).sort_values("Line", ascending=False)
        st.caption(f"{len(view):,} of {len(df):,} entries · `logs/triage_audit.log`")
        st.dataframe(view[["Line", "Time", "Level", "Category", "Message", "Chain"]], hide_index=True,
                     width="stretch", height=520,
                     column_config={
                         "Line": st.column_config.NumberColumn(width=70),
                         "Time": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss", width=170),
                         "Level": st.column_config.TextColumn(width=90),
                         "Category": st.column_config.TextColumn(width=170),
                         "Message": st.column_config.TextColumn(width="large"),
                         "Chain": st.column_config.TextColumn("Integrity", width=170),
                     })
        st.download_button("Download CSV", view.to_csv(index=False).encode("utf-8"),
                           file_name=f"audit_log_{datetime.now():%Y%m%d_%H%M%S}.csv", mime="text/csv",
                           icon=":material/download:", key="dl_all")


def render_users_page():
    me = st.session_state["auth_user"]
    ui.section("User management", "Create accounts, reset passwords and control access. Every change is audited.", "group")
    users = auth.list_users()
    ui.kpi_row([
        ui.kpi("Accounts", f"{len(users)}"),
        ui.kpi("Administrators", f"{sum(u['role'] == 'admin' for u in users)}"),
        ui.kpi("Active", f"{sum(u['active'] for u in users)}"),
        ui.kpi("Locked", f"{sum(u['locked'] for u in users)}",
               color=ui.WARNING if any(u["locked"] for u in users) else None),
    ])
    st.write("")
    table = pd.DataFrame([{
        "Username": u["username"], "Full name": u["full_name"], "Role": ROLE_LABELS[u["role"]],
        "Status": "🚫 Disabled" if not u["active"] else "🔒 Locked" if u["locked"] else "🟢 Active",
        "Must change password": u.get("must_change_password", False),
        "Last sign-in": local_time(u.get("last_login_utc")),
        "Created": f"{local_time(u.get('created_utc'))} by {u.get('created_by', '-')}",
    } for u in users])
    st.dataframe(table, hide_index=True, width="stretch",
                 column_config={"Must change password": st.column_config.CheckboxColumn(width=150)})

    c_new, c_manage = st.columns(2, gap="large")
    with c_new, st.container(border=True):
        st.markdown("##### Create user")
        with st.form("create_user", clear_on_submit=True, border=False):
            a, b = st.columns(2)
            username  = a.text_input("Username", placeholder="e.g. jdoe")
            full_name = b.text_input("Full name", placeholder="Name shown on case records")
            role      = st.radio("Role", auth.ROLES, format_func=ROLE_LABELS.get, horizontal=True, index=1)
            a, b = st.columns(2)
            password  = a.text_input("Temporary password", type="password")
            confirm   = b.text_input("Repeat password", type="password")
            st.caption("The user must choose a new password at first sign-in.")
            submitted = st.form_submit_button("Create user", type="primary", icon=":material/person_add:")
        if submitted:
            if password != confirm:
                st.error("Passwords do not match.")
            else:
                try:
                    auth.create_user(username, full_name, role, password, created_by=me["username"])
                except auth.AuthError as e:
                    st.error(str(e))
                else:
                    st.toast(f"User {username.strip().lower()} created", icon="➕")
                    st.rerun()

    with c_manage, st.container(border=True):
        st.markdown("##### Manage user")
        if not users:
            return
        target = st.selectbox("User", [u["username"] for u in users],
                              format_func=lambda n: f"{n} — {next(u['full_name'] for u in users if u['username'] == n)}")
        rec = next(u for u in users if u["username"] == target)
        try:
            a, b, c = st.columns([1, 1, 1.35])
            if rec["active"]:
                if a.button("Disable", icon=":material/block:", width="stretch"):
                    auth.set_active(target, False, by=me["username"]); st.rerun()
            elif a.button("Enable", icon=":material/check_circle:", width="stretch"):
                auth.set_active(target, True, by=me["username"]); st.rerun()
            if b.button("Unlock", icon=":material/lock_open:", width="stretch", disabled=not rec["locked"]):
                auth.unlock(target, by=me["username"]); st.rerun()
            new_role = c.selectbox("Role", auth.ROLES, index=auth.ROLES.index(rec["role"]),
                                   format_func=ROLE_LABELS.get, label_visibility="collapsed", key=f"role_{target}")
            if new_role != rec["role"]:
                auth.set_role(target, new_role, by=me["username"]); st.rerun()
            with st.form(f"reset_{target}", clear_on_submit=True, border=False):
                temp = st.text_input("New temporary password", type="password")
                if st.form_submit_button("Reset password", icon=":material/lock_reset:"):
                    auth.reset_password(target, temp, by=me["username"])
                    st.toast(f"Password reset for {target}", icon="🔁")
                    st.rerun()
        except auth.AuthError as e:
            st.error(str(e))


def render_account_page():
    me = st.session_state["auth_user"]
    ui.section("My account", "Your profile, password and recent sign-in activity.", "person")
    ui.kpi_row([
        ui.kpi("Name", ui.esc(me["full_name"]), ui.esc(me["username"]), small=True, wide=True),
        ui.kpi("Role", ROLE_LABELS[me["role"]], small=True),
        ui.kpi("Signed in", ui.esc(st.session_state["auth"]["login_local"]), small=True),
        ui.kpi("Account created", local_time(me.get("created_utc")), small=True),
    ])
    st.write("")
    c_pw, c_hist = st.columns([1, 1.6], gap="large")
    with c_pw, st.container(border=True):
        st.markdown("##### Change password")
        render_password_change(me)
    with c_hist, st.container(border=True):
        st.markdown("##### My recent sign-in activity")
        df, _ = load_audit()
        mine = df[(df["Category"] == "AUTH") & (df["User"] == me["username"]) &
                  df["Event"].isin(SIGNIN_EVENTS)] if not df.empty else df
        if mine.empty:
            st.caption("No activity recorded yet.")
        else:
            st.dataframe(mine.sort_values("Line", ascending=False).head(15)
                         .assign(Event=lambda d: d["Event"].map(SIGNIN_EVENTS))[["Time", "Event", "Client", "Details"]],
                         hide_index=True, width="stretch",
                         column_config={"Time": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss")})
