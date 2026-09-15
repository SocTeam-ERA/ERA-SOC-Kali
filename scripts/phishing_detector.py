#!/usr/bin/env python3
"""
phishing_detector.py
--------------------
Analyses email messages (.eml / RFC-822) and scores them for phishing and
malware indicators, then raises a SOC alert with a severity based on the score.

It is a static analyser (no sandbox, no clicking links) built from standard
SOC triage checks — the same things you do by hand in a LetsDefend email
lab, automated:

    Authentication   : SPF / DKIM / DMARC results in the headers
    Sender sanity    : From vs Reply-To vs Return-Path mismatch, display-name spoofing
    Links            : IP-literal URLs, URL shorteners, look-alike/@-trick URLs,
                       display-text vs real-href mismatch, punycode, credential pages
    Attachments      : dangerous extensions (.exe .scr .js .vbs .hta ...),
                       double extensions (invoice.pdf.exe), macro-enabled Office docs
    Content          : classic phishing lures (urgency, credentials, payment)

Usage:
    python3 phishing_detector.py suspicious.eml
    python3 phishing_detector.py /path/to/maildir/*.eml
    python3 phishing_detector.py --demo        # analyse a bundled sample email

Scoring -> severity:
    >= 8  critical    |    4-7  medium    |    1-3 normal (logged, low risk)
"""

from __future__ import annotations

import argparse
import email
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from pathlib import Path

from soc_core import Alert, emit_alert

DANGEROUS_EXT = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".hta", ".jar", ".ps1", ".msi", ".lnk", ".reg", ".cpl",
}
MACRO_OFFICE_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".gz"}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
}

LURE_PATTERNS = [
    (r"verify (your )?account", "credential lure"),
    (r"confirm your (password|identity|account)", "credential lure"),
    (r"unusual (sign[- ]?in|activity|login)", "account-security lure"),
    (r"your account (has been|will be) (suspended|locked|disabled)", "urgency/suspension lure"),
    (r"update (your )?(payment|billing) (info|information|details)", "payment lure"),
    (r"click (here|below) to", "click lure"),
    (r"within 24 hours|immediately|urgent action required", "urgency lure"),
    (r"invoice attached|see attached (invoice|document|payment)", "attachment lure"),
    (r"(gift card|wire transfer|bitcoin|crypto)", "financial-fraud lure"),
]

URL_RE = re.compile(r'https?://[^\s"\'<>)]+', re.IGNORECASE)
IP_URL_RE = re.compile(r'https?://\d{1,3}(?:\.\d{1,3}){3}', re.IGNORECASE)
HREF_RE = re.compile(r'<a\s[^>]*href=["\']?(https?://[^"\'>\s]+)["\']?[^>]*>(.*?)</a>',
                     re.IGNORECASE | re.DOTALL)


def domain_of(addr_or_url: str) -> str:
    s = addr_or_url.lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0].split("@")[-1]
    return s.split(":")[0]


def analyse(msg) -> tuple[int, list[str], dict]:
    """Return (score, reasons, details)."""
    score = 0
    reasons: list[str] = []
    details: dict = {}

    # ---- headers / authentication ---------------------------------------- #
    from_addr = parseaddr(msg.get("From", ""))[1]
    from_name = parseaddr(msg.get("From", ""))[0]
    reply_to = parseaddr(msg.get("Reply-To", ""))[1]
    return_path = parseaddr(msg.get("Return-Path", ""))[1]
    subject = str(msg.get("Subject", ""))
    details.update(from_addr=from_addr, subject=subject)

    auth_results = (msg.get("Authentication-Results", "") or "").lower()
    received_spf = (msg.get("Received-SPF", "") or "").lower()
    for mech, label in (("spf=fail", "SPF fail"), ("spf=softfail", "SPF softfail"),
                        ("dkim=fail", "DKIM fail"), ("dmarc=fail", "DMARC fail")):
        if mech in auth_results or (mech.startswith("spf") and mech.split("=")[1] in received_spf):
            # softfail is a weaker/ambiguous signal than a confirmed hard
            # fail, so it should score less -- note "softfail" also ends
            # with "fail", so an endswith("fail") check can't tell them
            # apart; compare the exact mechanism string instead.
            score += 2 if mech == "spf=softfail" else 3
            reasons.append(f"Email authentication: {label}")
    if "dmarc=none" in auth_results:
        score += 1
        reasons.append("No DMARC alignment (dmarc=none)")

    # From vs Reply-To / Return-Path mismatch
    if reply_to and domain_of(reply_to) != domain_of(from_addr):
        score += 2
        reasons.append(f"Reply-To domain ({domain_of(reply_to)}) differs from "
                       f"From domain ({domain_of(from_addr)})")
    if return_path and from_addr and domain_of(return_path) != domain_of(from_addr):
        score += 1
        reasons.append(f"Return-Path domain ({domain_of(return_path)}) differs from From")

    # Display-name spoofing: name claims a brand/person but address is elsewhere
    if from_name and "@" in from_name:
        score += 2
        reasons.append(f"Display name contains a second address: {from_name!r}")

    # ---- body: text + html ---------------------------------------------- #
    body_text = ""
    html = ""
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "text/plain":
            body_text += part.get_content() if part.get_content_maintype() == "text" else ""
        elif ctype == "text/html":
            try:
                html += part.get_content()
            except Exception:
                pass
    corpus = f"{subject}\n{body_text}\n{html}".lower()

    # lures
    hit_lures = []
    for pat, label in LURE_PATTERNS:
        if re.search(pat, corpus):
            hit_lures.append(label)
    if hit_lures:
        score += min(len(set(hit_lures)), 3)
        reasons.append("Phishing lure language: " + ", ".join(sorted(set(hit_lures))))

    # ---- URLs ------------------------------------------------------------ #
    urls = set(URL_RE.findall(body_text)) | set(URL_RE.findall(html))
    bad_urls = []
    if IP_URL_RE.search("\n".join(urls)):
        score += 3
        reasons.append("Link points directly to a raw IP address")
    for u in urls:
        dom = domain_of(u)
        if dom in URL_SHORTENERS:
            score += 2
            bad_urls.append(u)
            reasons.append(f"URL shortener hides destination: {dom}")
        if "xn--" in dom:
            score += 2
            bad_urls.append(u)
            reasons.append(f"Punycode / IDN homograph domain: {dom}")
        if "@" in u.split("//", 1)[-1].split("/", 1)[0]:
            score += 3
            bad_urls.append(u)
            reasons.append("'@' trick in URL authority (real host hidden)")

    # display text vs real href mismatch (classic)
    for href, text in HREF_RE.findall(html):
        text_clean = re.sub(r"<[^>]+>", "", text).strip()
        if text_clean.startswith("http"):
            if domain_of(text_clean) and domain_of(href) and \
               domain_of(text_clean) != domain_of(href):
                score += 3
                bad_urls.append(href)
                reasons.append(f"Link text shows {domain_of(text_clean)} but really goes to "
                               f"{domain_of(href)}")

    details["urls"] = sorted(urls)[:20]
    details["suspicious_urls"] = sorted(set(bad_urls))[:20]

    # ---- attachments ----------------------------------------------------- #
    bad_attachments = []
    for part in msg.walk():
        fn = part.get_filename()
        if not fn:
            continue
        low = fn.lower()
        suffixes = Path(low).suffixes
        ext = suffixes[-1] if suffixes else ""
        if ext in DANGEROUS_EXT:
            score += 5
            bad_attachments.append(fn)
            reasons.append(f"Dangerous executable attachment: {fn}")
        elif ext in MACRO_OFFICE_EXT:
            score += 3
            bad_attachments.append(fn)
            reasons.append(f"Macro-enabled Office attachment: {fn}")
        elif ext in ARCHIVE_EXT:
            score += 1
            bad_attachments.append(fn)
            reasons.append(f"Archive attachment (may hide payload): {fn}")
        if len(suffixes) >= 2 and suffixes[-1] in DANGEROUS_EXT:
            score += 3
            reasons.append(f"Double extension disguises executable: {fn}")
    details["attachments"] = bad_attachments

    return score, reasons, details


def score_to_severity(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 4:
        return "medium"
    return "normal"


def analyse_file(path: Path) -> None:
    with path.open("rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    score, reasons, details = analyse(msg)
    if score == 0:
        print(f"[ok] {path.name}: no phishing indicators", file=sys.stderr)
        return
    severity = score_to_severity(score)
    sender_ip = None
    # try to pull the originating IP from the earliest Received header
    for h in reversed(msg.get_all("Received", [])):
        m = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", h)
        if m:
            sender_ip = m.group(1)
            break
    emit_alert(Alert(
        type="phishing", severity=severity,
        title=f"Phishing indicators in email: {details.get('subject', '(no subject)')[:80]}",
        source_ip=sender_ip,
        user=details.get("from_addr"),
        detector="phishing_detector",
        description=f"Suspicious email from {details.get('from_addr')} scored {score}. "
                    + " | ".join(reasons[:6]),
        details={"score": score, "reasons": reasons, **details, "file": str(path)},
    ))


DEMO_EML = """From: "Microsoft Account Team" <security@micros0ft-support.com>
Reply-To: harvest@mail.ru
Return-Path: <bounce@sketchy-mailer.ru>
To: jsmith@yourcompany.com
Subject: Unusual sign-in activity - verify your account within 24 hours
Authentication-Results: mx.yourcompany.com; spf=fail smtp.mailfrom=micros0ft-support.com; dkim=fail; dmarc=fail
Received: from unknown ([203.0.113.66]) by mx.yourcompany.com
Content-Type: text/html

<html><body>
<p>We detected unusual sign-in activity. You must
<a href="http://198.51.100.23/login/office365">https://login.microsoftonline.com</a>
confirm your password immediately or your account will be suspended.</p>
<p>Please see attached invoice.</p>
</body></html>
"""


def run_demo() -> None:
    print("[*] Demo mode: analysing a bundled sample phishing email...", file=sys.stderr)
    msg = email.message_from_string(DEMO_EML, policy=policy.default)
    score, reasons, details = analyse(msg)
    severity = score_to_severity(score)
    emit_alert(Alert(
        type="phishing", severity=severity,
        title=f"Phishing indicators in email: {details.get('subject')[:80]}",
        source_ip="203.0.113.66", user=details.get("from_addr"),
        detector="phishing_detector",
        description=f"Sample email scored {score}. " + " | ".join(reasons[:6]),
        details={"score": score, "reasons": reasons, **details},
    ))
    print("\nIndicators found:", file=sys.stderr)
    for r in reasons:
        print(f"  - {r}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description="Phishing email analyser -> SOC alerts")
    ap.add_argument("files", nargs="*", help=".eml files to analyse")
    ap.add_argument("--demo", action="store_true", help="Analyse a bundled sample email")
    args = ap.parse_args()

    if args.demo:
        run_demo()
        return 0
    if not args.files:
        ap.error("give one or more .eml files, or --demo")
    for f in args.files:
        p = Path(f)
        if p.exists():
            analyse_file(p)
        else:
            print(f"[!] not found: {f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
