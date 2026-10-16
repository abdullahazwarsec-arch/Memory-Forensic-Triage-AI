"""
User Accounts & Authentication
==============================
Local user accounts for the triage dashboard.

* Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes (600,000 iterations).
* The account store (keys/users.json, git-ignored) is sealed with an HMAC keyed
  with the custody-ledger key, so accounts cannot be added or edited by hand.
* After 5 consecutive failed sign-ins an account is locked for 15 minutes.
* Roles: "admin" (manage users, read the audit log) and "analyst" (triage).
* Every authentication and account event is written to the HMAC-chained audit
  log as an "AUTH | EVENT=... | USER=..." line, which the Audit Log page reads.

Recovery from the command line:  python scripts/admin/manage_users.py --help
"""

import os
import re
import hmac
import json
import time
import secrets
import hashlib
import logging
import threading
from datetime import datetime, timezone, timedelta

from . import evidence_integrity as ei


USERS_PATH       = os.environ.get("HAZMEM_USERS_FILE") or os.path.join(ei.BASE_DIR, "keys", "users.json")
ROLES            = ("admin", "analyst")
PBKDF2_ITER      = 600_000
MAX_FAILED       = 5
LOCKOUT_MINUTES  = 15
IDLE_TIMEOUT_MIN = 30
MIN_PASSWORD_LEN = 10
USERNAME_RE      = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")

_lock   = threading.Lock()
_log    = logging.getLogger("triage.auth")
_DUMMY  = None   # hash used to equalise timing for unknown usernames


class AuthError(Exception):
    """A user-management request was refused (validation or policy)."""


class UserStoreTampered(Exception):
    """users.json was modified outside the application (HMAC mismatch)."""


# ── Audit events ──────────────────────────────────────────────────────────────
def _field(value) -> str:
    """Make a value safe for the 'KEY=value | ...' log format (no separators, no line breaks)."""
    return re.sub(r"[|=\r\n]", "/", str(value)).strip()[:120] or "-"


def audit(event: str, user: str, level: int = logging.INFO, **fields):
    extra = "".join(f" | {k.upper()}={_field(v)}" for k, v in fields.items() if v not in (None, ""))
    _log.log(level, f"AUTH | EVENT={event} | USER={_field(user)}{extra}")


# ── Password hashing ──────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(candidate.hex(), digest)
    except (ValueError, AttributeError):
        return False


def password_problems(password: str, username: str = "") -> list:
    problems = []
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"at least {MIN_PASSWORD_LEN} characters")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("both letters and digits")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    return problems


def _check_password(password: str, username: str):
    problems = password_problems(password, username)
    if problems:
        raise AuthError("Password needs " + ", ".join(problems) + ".")


# ── Store (HMAC-sealed JSON) ──────────────────────────────────────────────────
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _seal(users: dict) -> str:
    payload = json.dumps(users, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(ei.ledger_key(), b"users|" + payload, hashlib.sha256).hexdigest()


def _load() -> dict:
    if not os.path.isfile(USERS_PATH):
        return {}
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    users = data.get("users", {})
    if not hmac.compare_digest(_seal(users), str(data.get("hmac", ""))):
        raise UserStoreTampered(f"{USERS_PATH} was modified outside the application - sign-in is disabled "
                                "until the account store is restored from a trusted copy.")
    return users


def _save(users: dict):
    os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
    tmp = f"{USERS_PATH}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"format": 1, "users": users, "hmac": _seal(users)}, f, indent=2)
    os.replace(tmp, USERS_PATH)


def _public(username: str, rec: dict) -> dict:
    """User record without the password hash."""
    out = {k: v for k, v in rec.items() if k != "password_hash"}
    out["username"] = username
    out["locked"] = is_locked(rec)
    return out


def is_locked(rec: dict) -> bool:
    until = rec.get("locked_until")
    return bool(until) and datetime.strptime(until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) > _now()


# ── Queries ───────────────────────────────────────────────────────────────────
def has_users() -> bool:
    return bool(_load())


def get_user(username: str) -> dict:
    rec = _load().get(username)
    return _public(username, rec) if rec else None


def list_users() -> list:
    return [_public(u, r) for u, r in sorted(_load().items())]


# ── Authentication ────────────────────────────────────────────────────────────
def authenticate(username: str, password: str, client: str = "") -> dict:
    """
    Returns the public user record on success, or None. Failures are logged
    with their precise reason; callers should show only a generic message.
    """
    global _DUMMY
    username = (username or "").strip().lower()
    with _lock:
        users = _load()
        rec = users.get(username)
        if rec is None:
            _DUMMY = _DUMMY or hash_password(secrets.token_hex(8))
            verify_password(password, _DUMMY)   # same cost as a real check (no username probing by timing)
            audit("LOGIN_FAILED", username if USERNAME_RE.match(username) else "<invalid>",
                  logging.WARNING, reason="unknown user", client=client)
            return None
        if not rec.get("active", True):
            audit("LOGIN_FAILED", username, logging.WARNING, reason="account disabled", client=client)
            return None
        if is_locked(rec):
            audit("LOGIN_FAILED", username, logging.WARNING, reason="account locked", client=client)
            return None
        if not verify_password(password, rec["password_hash"]):
            rec["failed_attempts"] = rec.get("failed_attempts", 0) + 1
            audit("LOGIN_FAILED", username, logging.WARNING, reason="wrong password",
                  attempt=f"{rec['failed_attempts']}/{MAX_FAILED}", client=client)
            if rec["failed_attempts"] >= MAX_FAILED:
                rec["locked_until"] = _iso(_now() + timedelta(minutes=LOCKOUT_MINUTES))
                rec["failed_attempts"] = 0
                audit("ACCOUNT_LOCKED", username, logging.WARNING,
                      reason=f"{MAX_FAILED} failed sign-ins", until=rec["locked_until"], client=client)
            _save(users)
            return None
        rec["failed_attempts"], rec["locked_until"] = 0, None
        rec["last_login_utc"] = _iso(_now())
        _save(users)
        return _public(username, rec)


# ── Account management ────────────────────────────────────────────────────────
def create_user(username: str, full_name: str, role: str, password: str, created_by: str,
                must_change_password: bool = True) -> dict:
    username, full_name = (username or "").strip().lower(), " ".join((full_name or "").split())
    if not USERNAME_RE.match(username):
        raise AuthError("Username must be 3-32 characters: lowercase letters, digits, '.', '_' or '-'.")
    if len(full_name) < 3:
        raise AuthError("Full name must be at least 3 characters.")
    if role not in ROLES:
        raise AuthError(f"Role must be one of: {', '.join(ROLES)}.")
    _check_password(password, username)
    with _lock:
        users = _load()
        if username in users:
            raise AuthError(f"User '{username}' already exists.")
        users[username] = {
            "full_name": full_name, "role": role, "password_hash": hash_password(password),
            "active": True, "must_change_password": must_change_password,
            "created_utc": _iso(_now()), "created_by": created_by,
            "last_login_utc": None, "failed_attempts": 0, "locked_until": None,
        }
        _save(users)
    audit("USER_CREATED", username, role=role, name=full_name, by=created_by)
    return get_user(username)


def change_password(username: str, current: str, new: str) -> None:
    """Self-service change: requires the current password."""
    with _lock:
        users = _load()
        rec = users.get(username)
        if rec is None or not verify_password(current, rec["password_hash"]):
            audit("PASSWORD_CHANGE_FAILED", username, logging.WARNING, reason="current password incorrect")
            raise AuthError("Current password is incorrect.")
        if verify_password(new, rec["password_hash"]):
            raise AuthError("The new password must differ from the current one.")
        _check_password(new, username)
        rec["password_hash"], rec["must_change_password"] = hash_password(new), False
        _save(users)
    audit("PASSWORD_CHANGED", username, by=username)


def _admin_update(username: str, by: str, event: str, mutate, **fields):
    with _lock:
        users = _load()
        if username not in users:
            raise AuthError(f"User '{username}' does not exist.")
        mutate(users[username], users)
        _save(users)
    audit(event, username, by=by, **fields)


def _active_admins(users: dict) -> int:
    return sum(1 for r in users.values() if r["role"] == "admin" and r.get("active", True))


def reset_password(username: str, new_password: str, by: str):
    _check_password(new_password, username)

    def mutate(rec, _):
        rec.update(password_hash=hash_password(new_password), must_change_password=True,
                   failed_attempts=0, locked_until=None)
    _admin_update(username, by, "PASSWORD_RESET", mutate)


def set_active(username: str, active: bool, by: str):
    def mutate(rec, users):
        if not active and username == by:
            raise AuthError("You cannot disable your own account.")
        if not active and rec["role"] == "admin" and _active_admins(users) <= 1:
            raise AuthError("At least one active administrator must remain.")
        rec["active"] = active
    _admin_update(username, by, "USER_ENABLED" if active else "USER_DISABLED", mutate)


def set_role(username: str, role: str, by: str):
    if role not in ROLES:
        raise AuthError(f"Role must be one of: {', '.join(ROLES)}.")

    def mutate(rec, users):
        if rec["role"] == "admin" and role != "admin":
            if username == by:
                raise AuthError("You cannot remove your own administrator role.")
            if _active_admins(users) <= 1:
                raise AuthError("At least one active administrator must remain.")
        rec["role"] = role
    _admin_update(username, by, "ROLE_CHANGED", mutate, role=role)


def unlock(username: str, by: str):
    _admin_update(username, by, "USER_UNLOCKED",
                  lambda rec, _: rec.update(failed_attempts=0, locked_until=None))


PREFERENCES = {"theme": ("light", "dark", "auto"), "view": ("simple", "expert")}


def set_preference(username: str, key: str, value: str):
    """Store a harmless per-user display preference (validated against PREFERENCES)."""
    if value not in PREFERENCES.get(key, ()):
        raise AuthError(f"Invalid value for preference '{key}'.")
    with _lock:
        users = _load()
        if username not in users:
            raise AuthError(f"User '{username}' does not exist.")
        users[username].setdefault("preferences", {})[key] = value
        _save(users)


def session_expired(last_seen: float) -> bool:
    return time.time() - last_seen > IDLE_TIMEOUT_MIN * 60
