"""
Dashboard account administration from the command line (e.g. when the only
administrator is locked out or has forgotten their password). Every action is
written to the audit log, attributed to "cli:<OS user>".

    python scripts/manage_users.py list
    python scripts/manage_users.py create <username> "<Full Name>" --role admin
    python scripts/manage_users.py reset-password <username>
    python scripts/manage_users.py unlock <username>
    python scripts/manage_users.py enable <username>
"""
import os
import sys
import getpass
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

import audit_log
import auth

audit_log.setup(os.environ.get("MEMTRIAGE_AUDIT_LOG") or str(BASE_DIR / "logs" / "triage_audit.log"))
ACTOR = f"cli:{getpass.getuser()}"


def ask_password(username: str) -> str:
    while True:
        pw = getpass.getpass(f"New password for {username}: ")
        problems = auth.password_problems(pw, username)
        if problems:
            print("  Password needs " + ", ".join(problems) + ".")
        elif pw != getpass.getpass("Repeat password: "):
            print("  Passwords do not match.")
        else:
            return pw


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p = sub.add_parser("create"); p.add_argument("username"); p.add_argument("full_name")
    p.add_argument("--role", choices=auth.ROLES, default="analyst")
    for name in ("reset-password", "unlock", "enable"):
        sub.add_parser(name).add_argument("username")
    args = parser.parse_args()

    try:
        if args.cmd == "list":
            for u in auth.list_users():
                state = "disabled" if not u["active"] else "locked" if u["locked"] else "active"
                print(f"{u['username']:<20} {u['role']:<8} {state:<9} {u['full_name']}  "
                      f"(last login {u['last_login_utc'] or 'never'})")
        elif args.cmd == "create":
            auth.create_user(args.username, args.full_name, args.role, ask_password(args.username), ACTOR)
            print(f"Created {args.role} '{args.username}' (must change password at first sign-in).")
        elif args.cmd == "reset-password":
            auth.reset_password(args.username, ask_password(args.username), ACTOR)
            print(f"Password reset for '{args.username}' (must change it at next sign-in); account unlocked.")
        elif args.cmd == "unlock":
            auth.unlock(args.username, ACTOR)
            print(f"Unlocked '{args.username}'.")
        elif args.cmd == "enable":
            auth.set_active(args.username, True, ACTOR)
            print(f"Enabled '{args.username}'.")
    except (auth.AuthError, auth.UserStoreTampered) as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
