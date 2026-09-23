#!/usr/bin/env python3
"""
ad_risks.py
-----------
The Active Directory weaknesses attackers go for first, read with the SOC's plain
Domain Users account (the same one scripts/ad_inventory.py uses; nothing here needs
privilege, which is exactly why an attacker who phishes any employee can find them too).

Checked daily from ad_inventory.py; every finding groups the accounts it applies to:
  * kerberoastable      user accounts with a servicePrincipalName: any domain user can ask
                        for a ticket encrypted with that account's password and crack it
                        offline, unseen (MITRE T1558.003). Critical when the account is
                        privileged.
  * asrep_roastable     "Do not require Kerberos preauthentication": same, without even
                        needing a domain account (T1558.004).
  * unconstrained_delegation
                        computers (other than DCs) or users trusted for unconstrained
                        delegation: whoever controls one can impersonate any user that
                        connects to it, including admins.
  * password_not_required, reversible_encryption
                        account flags that allow an empty password / store it recoverably.
  * privileged_old_password, privileged_stale
                        admin accounts whose password is over a year old, or that have not
                        signed in for STALE_DAYS but are still enabled.
  * krbtgt_old_password the key that signs every Kerberos ticket; unchanged for years means
                        a stolen copy ("golden ticket") keeps working.
  * weak_password_policy / no_lockout
                        the default domain policy (fine-grained policies are not read).
  * laps_missing        workstations without a managed local administrator password
                        (only the expiry attribute is read, never a password).

Everything is pure except read_risk_data(); the checks are unit-tested in soc_selftest.py.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

ACCOUNTDISABLE = 0x2
PASSWD_NOTREQD = 0x20
ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
SERVER_TRUST_ACCOUNT = 0x2000          # domain controller computer account
DONT_EXPIRE_PASSWORD = 0x10000
TRUSTED_FOR_DELEGATION = 0x80000       # unconstrained delegation
DONT_REQ_PREAUTH = 0x400000
PARTIAL_SECRETS_ACCOUNT = 0x4000000    # read-only DC

STALE_DAYS = 90
OLD_PASSWORD_DAYS = 365
KRBTGT_MAX_DAYS = 180
MIN_PASSWORD_LENGTH = 12
LAPS_ATTRS = ("msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime")


def _first(v):
    return (v[0] if v else None) if isinstance(v, list) else v


def _date(v) -> Optional[str]:
    if isinstance(v, datetime) and v.year > 1601:
        return v.date().isoformat()
    return None


def _days(interval) -> Optional[int]:
    """AD intervals (maxPwdAge...) come as a timedelta through the schema, or as a raw negative
    count of 100 ns ticks without it."""
    if isinstance(interval, timedelta):
        return abs(interval).days
    try:
        return abs(int(interval)) // (10_000_000 * 86400)
    except (TypeError, ValueError):
        return None


def read_risk_data(conn, base: str, search: Callable[[Any, str, str, List[str]], List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Accounts (users and computers) with the attributes the checks need, and the domain policy."""
    from ldap3 import BASE
    schema = getattr(conn.server, "schema", None)
    laps = [a for a in LAPS_ATTRS if schema is None or a in schema.attribute_types]
    attrs = ["sAMAccountName", "objectClass", "userAccountControl", "servicePrincipalName", "pwdLastSet",
             "lastLogonTimestamp", "adminCount", "operatingSystem"] + laps
    accounts = []
    for a in search(conn, base, "(objectClass=user)", attrs):
        sam = str(_first(a.get("sAMAccountName")) or "")
        if not sam:
            continue
        classes = [str(c).lower() for c in (a.get("objectClass") or [])]
        accounts.append({
            "sam": sam, "computer": "computer" in classes,
            "uac": int(_first(a.get("userAccountControl")) or 0),
            "spn": [str(s) for s in (a.get("servicePrincipalName") or [])],
            "pwd_last_set": _date(a.get("pwdLastSet")),
            "last_logon": _date(a.get("lastLogonTimestamp")),
            "admin_count": int(_first(a.get("adminCount")) or 0),
            "os": _first(a.get("operatingSystem")),
            "laps": any(a.get(x) for x in laps),
        })
    conn.search(base, "(objectClass=domain)", BASE,
                attributes=["minPwdLength", "lockoutThreshold", "maxPwdAge", "pwdHistoryLength"])
    e = conn.entries[0].entry_attributes_as_dict if conn.entries else {}
    policy = {"min_length": _first(e.get("minPwdLength")), "lockout_threshold": _first(e.get("lockoutThreshold")),
              "max_age_days": _days(_first(e.get("maxPwdAge"))), "history": _first(e.get("pwdHistoryLength"))}
    return {"accounts": accounts, "policy": policy, "laps_in_schema": bool(laps)}


def _age(iso: Optional[str], today: date) -> Optional[int]:
    return (today - date.fromisoformat(iso)).days if iso else None


def risk_findings(data: Dict[str, Any], privileged: Iterable[str], today: date) -> List[Dict[str, Any]]:
    """[{"id", "severity", "title", "description", "accounts", "mitre"}] -- one per weakness present."""
    priv = {p.lower() for p in privileged}
    out: List[Dict[str, Any]] = []
    enabled = [a for a in data["accounts"] if not a["uac"] & ACCOUNTDISABLE]
    users = [a for a in enabled if not a["computer"]]

    def add(fid, severity, title, description, accounts, mitre=None):
        if accounts:
            out.append({"id": fid, "severity": severity, "title": title, "description": description,
                        "accounts": sorted(accounts, key=str.lower), "mitre": mitre})

    roast = [a for a in users if a["spn"] and a["sam"].lower() != "krbtgt"]
    for fid, sev, group in (("kerberoastable_privileged", "critical", [a for a in roast if a["sam"].lower() in priv]),
                            ("kerberoastable", "medium", [a for a in roast if a["sam"].lower() not in priv])):
        add(fid, sev, f"Kerberoastable {'privileged ' if sev == 'critical' else ''}account(s) in AD",
            ("These user accounts have a service principal name, so any domain user can request a Kerberos ticket "
             "encrypted with the account's password and try to crack it offline, without failed logins or lockouts. "
             + ("They are privileged, so cracking one gives the whole domain. " if sev == "critical" else "")
             + "Fix: remove SPNs that are not used, or give the account a 25+ character random password (or move the "
               "service to a group managed service account). Password last set: "
             + ", ".join(f"{a['sam']} {a['pwd_last_set'] or 'never'}" for a in group) + "."),
            [a["sam"] for a in group], "T1558.003")
    asrep = [a for a in users if a["uac"] & DONT_REQ_PREAUTH]
    add("asrep_roastable", "critical" if any(a["sam"].lower() in priv for a in asrep) else "medium",
        "AD account(s) without Kerberos pre-authentication",
        ("'Do not require Kerberos preauthentication' is set, so anyone on the network can obtain material to crack "
         "these passwords offline, without even having a domain account. Fix: clear that option on the account."),
        [a["sam"] for a in asrep], "T1558.004")
    deleg = [a for a in enabled if a["uac"] & TRUSTED_FOR_DELEGATION
             and not a["uac"] & (SERVER_TRUST_ACCOUNT | PARTIAL_SECRETS_ACCOUNT)]
    add("unconstrained_delegation", "critical" if any(not a["computer"] for a in deleg) else "medium",
        "Unconstrained delegation outside the domain controllers",
        ("These accounts are 'trusted for delegation to any service'. Whoever takes control of one can capture the "
         "Kerberos ticket of every user that connects to it, admins included, and reuse it anywhere. Fix: switch to "
         "constrained delegation, or remove delegation."),
        [a["sam"] for a in deleg], "T1558")
    add("password_not_required", "medium", "AD account(s) allowed to have an empty password",
        ("The PASSWD_NOTREQD flag lets these accounts have an empty password, whatever the domain policy says. "
         "Fix: Set-ADUser <name> -PasswordNotRequired $false, then set a password."),
        [a["sam"] for a in users if a["uac"] & PASSWD_NOTREQD])
    add("reversible_encryption", "medium", "AD account(s) storing the password with reversible encryption",
        "The password is stored in a form that can be decrypted. Fix: clear the option and reset the password.",
        [a["sam"] for a in users if a["uac"] & ENCRYPTED_TEXT_PWD_ALLOWED])

    padmins = [a for a in users if a["sam"].lower() in priv]
    add("privileged_old_password", "medium", f"Admin account(s) with a password older than {OLD_PASSWORD_DAYS} days",
        ("These privileged accounts have not changed their password in over a year, so a password leaked long ago "
         "would still work. Last set: "
         + ", ".join(f"{a['sam']} {a['pwd_last_set'] or 'never'}" for a in padmins
                     if (_age(a["pwd_last_set"], today) or 10**6) > OLD_PASSWORD_DAYS) + "."),
        [a["sam"] for a in padmins if (_age(a["pwd_last_set"], today) or 10**6) > OLD_PASSWORD_DAYS])
    add("privileged_stale", "medium", f"Enabled admin account(s) unused for {STALE_DAYS}+ days",
        ("Privileged accounts that nobody uses but that still work are ideal for an attacker: full rights, and "
         "nobody notices. Fix: disable them or remove them from the privileged groups."),
        [a["sam"] for a in padmins if (_age(a["last_logon"], today) or 10**6) > STALE_DAYS])

    krbtgt = next((a for a in data["accounts"] if a["sam"].lower() == "krbtgt"), None)
    k_age = _age(krbtgt["pwd_last_set"], today) if krbtgt else None
    if k_age is not None and k_age > KRBTGT_MAX_DAYS:
        add("krbtgt_old_password", "medium", f"krbtgt password not changed in {k_age} days",
            (f"krbtgt signs every Kerberos ticket in the domain; its password was last set on {krbtgt['pwd_last_set']}. "
             "If a copy was ever stolen, forged 'golden tickets' keep working until it is changed. Fix: reset it "
             "twice, some hours apart (Microsoft's New-KrbtgtKeys.ps1), and then every 180 days."),
            ["krbtgt"], "T1558.001")

    pol = data.get("policy") or {}
    if pol.get("min_length") is not None and int(pol["min_length"]) < MIN_PASSWORD_LENGTH:
        add("weak_password_policy", "medium",
            "Domain password policy has no minimum length" if int(pol["min_length"]) == 0
            else f"Domain password policy allows {pol['min_length']}-character passwords",
            (f"The default domain policy requires only {pol['min_length']} characters (history {pol.get('history')}, "
             f"maximum age {pol.get('max_age_days')} days). Short passwords fall to guessing and cracking. "
             f"Fix: at least {MIN_PASSWORD_LENGTH}-14 characters (fine-grained policies, if any, are not checked here)."),
            ["Default Domain Policy"], "T1110")
    if pol.get("lockout_threshold") is not None and int(pol["lockout_threshold"]) == 0:
        add("no_lockout", "medium", "Domain accounts never lock out after failed passwords",
            ("The lockout threshold is 0, so an attacker can try passwords against any account forever. "
             "Fix: lock after 10 or so failures for 15 minutes."),
            ["Default Domain Policy"], "T1110")

    if data.get("laps_in_schema") is not None:
        workstations = [a for a in enabled if a["computer"] and "server" not in str(a.get("os") or "").lower()
                        and not a["uac"] & (SERVER_TRUST_ACCOUNT | PARTIAL_SECRETS_ACCOUNT)
                        and (_age(a["last_logon"], today) or 10**6) <= STALE_DAYS]
        missing = [a["sam"].rstrip("$") for a in workstations if not a["laps"]]
        if missing:
            add("laps_missing", "medium" if len(missing) == len(workstations) else "normal",
                (f"LAPS not deployed on {len(missing)} of {len(workstations)} active workstations"),
                ("Without LAPS the built-in local administrator usually has the same password on every PC, so one "
                 "stolen hash opens them all (lateral movement). Fix: roll out Windows LAPS by group policy."
                 + ("" if data.get("laps_in_schema") else " The LAPS attributes are not even in the AD schema.")),
                missing, "T1550.002")
    return out
