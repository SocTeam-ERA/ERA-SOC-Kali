#!/usr/bin/env python3
"""Manage per-user Sentinel SOC API keys (data/api_keys.json).

Usage:
    python3 manage_api_keys.py list
    python3 manage_api_keys.py add <user> <read|write>
    python3 manage_api_keys.py revoke <user>

Changes only take effect after the API reloads them: restart the service
with `sudo systemctl restart soc-api`.
"""
from __future__ import annotations
import secrets
import sys

import soc_core


def cmd_list() -> None:
    keys = soc_core.load_api_keys()
    if not keys:
        print("(no keys configured)")
        return
    for k in keys:
        masked = k["token"][:4] + "…" + k["token"][-4:]
        print(f"{k['user']:<20} {k['role']:<6} {masked}")


def cmd_add(user: str, role: str) -> None:
    if role not in soc_core.VALID_API_ROLES:
        sys.exit(f"role must be one of {soc_core.VALID_API_ROLES}")
    keys = soc_core.load_api_keys()
    if any(k["user"] == user for k in keys):
        sys.exit(f"user {user!r} already has a key -- revoke it first to reissue")
    token = secrets.token_urlsafe(24)
    keys.append({"token": token, "user": user, "role": role})
    soc_core.save_api_keys(keys)
    print(f"Added a {role} key for {user!r}. This is the only time the full token is shown:")
    print(f"  {token}")
    print("Restart the API for it to take effect: sudo systemctl restart soc-api")


def cmd_revoke(user: str) -> None:
    keys = soc_core.load_api_keys()
    remaining = [k for k in keys if k["user"] != user]
    if len(remaining) == len(keys):
        sys.exit(f"no key found for user {user!r}")
    soc_core.save_api_keys(remaining)
    print(f"Revoked the key for {user!r}. Restart the API for it to take effect: sudo systemctl restart soc-api")


def main() -> None:
    args = sys.argv[1:]
    if args == ["list"]:
        cmd_list()
    elif len(args) == 3 and args[0] == "add":
        cmd_add(args[1], args[2])
    elif len(args) == 2 and args[0] == "revoke":
        cmd_revoke(args[1])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
