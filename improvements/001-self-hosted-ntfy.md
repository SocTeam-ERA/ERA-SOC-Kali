# 001: Self-hosted ntfy server for critical alert pushes

- **Status:** Proposed
- **Proposed:** 2026-09-23 by Arturo
- **Effort:** medium (a small code change; most of the work is the server and IT involvement)

## Problem

Critical alerts reach the phone through the public server `https://ntfy.sh` (`NTFY_URL` in
`scripts/soc_core.py`). Each push carries the alert title, up to 2,000 characters of its description, the
source IP, the hostname and the detector. That can include internal IPs, machine names and Active Directory
account names, so this data passes through a third-party server outside ERA.

The public server has no user or password on a topic. Its only protection is that nobody else knows the
topic name. Anyone who learns the topic can read every critical alert and publish fake ones.

## Proposal

Run ntfy (open source, Apache 2.0 / GPLv2) on an ERA server and point the Kali at it:

1. Install ntfy on an internal host or container, for example next to the platform in Dokploy, with HTTPS.
2. Turn on access control (`auth-default-access: deny-all`) and create:
   - a publish-only user or token for the Kali
   - a read-only user for each phone
3. Add support for an access token to `_ntfy_push()` in `scripts/soc_core.py`. Today it sends no
   authentication. The change is to read `NTFY_TOKEN` and send `Authorization: Bearer <token>`.
4. Set `NTFY_URL` and `NTFY_TOKEN` in the private `ntfy.conf` drop-ins. `deploy/install_all.sh` would
   write both, the same way it writes `NTFY_TOPIC` today.
5. On each phone, add the internal server and its user to the ntfy app.

## What it takes

- A server or container inside ERA, and a way for phones to reach it off the office network (VPN, or
  publishing it through the existing Cloudflare setup). **This is the decision that needs IT.**
- About 10 lines in `soc_core.py`, a self-test check, and an `install_all.sh` change for the token.
- A test period where the Kali pushes to both servers before switching off `ntfy.sh`.

## Risks and open questions

- **Availability:** today the push works even when ERA's infrastructure is down, because ntfy.sh is
  outside it. A self-hosted server that goes down together with the network would silence the alerts
  when they matter most. One option is to keep ntfy.sh as a fallback carrying only a minimal message such
  as "Critical alert on the SOC, check the dashboard", with no internal details.
- **iOS delivery:** a self-hosted server relies on ntfy.sh's upstream relay to wake iPhones instant-push.
  Only a message ID goes through the relay, not the content, but that needs confirming.
- Who runs and patches the server.

## Smaller step available now

If the full server is not approved, `_alert_body()` could send only the title and severity to ntfy.sh,
leaving IPs, hostnames and account names in the dashboard. That reduces what leaves ERA with no new
infrastructure.
