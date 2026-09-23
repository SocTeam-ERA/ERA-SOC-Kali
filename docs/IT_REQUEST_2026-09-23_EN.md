# Request to IT: what the Sentinel SOC needs, and why

**From:** Arturo Delcueto, Sentinel SOC (soc@era.ca)
**Date:** 2026-09-23
**Status of the project:** Phase 1 (detection only). Nothing described here changes, blocks or attacks anything on the network.

---

## 1. In short

We built a security monitoring appliance (a "SOC in a box") that runs on a Kali Linux virtual machine, `kali2` (10.69.0.40), plugged into all six of our networks. It watches for intruders, compromised machines, rogue devices, risky configurations and known-bad traffic, raises alerts on a dashboard (`soc.era.ca`) and pushes urgent ones to a phone.

It works, and it has already found real problems (Section 4). But **it is watching through a keyhole**: from where it sits it can see only the traffic that is broadcast to everyone, not the conversations between machines. To do the job properly it needs **three things from IT**:

| # | What we need | Why, in one line | Effort for IT |
|---|---|---|---|
| **A** | A **mirror (SPAN) port** copying traffic to Kali | Today we see about 1% of network activity; with a mirror we see the rest | Small: one switch/vSwitch setting |
| **B** | **Windows event logs** forwarded from the domain controllers (DC1, DC3) | Attacks on accounts and the domain leave their evidence there, not on the network | Small to medium: a Group Policy and a collector |
| **C** | **DNS, firewall/VPN and Microsoft 365 / Entra sign-in logs** sent to Kali | These are the three places where phishing, stolen passwords and outside attackers show up | Depends on the products; usually a setting |

We also ask IT to act on **findings the SOC has already made** (Section 4) and to answer **six short questions** (Section 5).

Everything is read-only: we receive copies of data. We do not need administrator rights on any machine, and we do not change any configuration.

---

## 2. What the SOC does today

- **Discovers devices** on every network (ARP sweep every 4 hours) and alerts on new or changed devices, MAC/IP conflicts and unknown machines.
- **Scans** every host (nmap: open ports, service versions, operating system, default safety checks) and once a week does a deeper vulnerability scan (Sunday 02:00).
- **Inspects traffic it can see** with Zeek and Suricata (intrusion detection), and watches DNS names against known-bad lists and threat-intelligence feeds.
- **Watches Kali itself**: logins, file changes, rootkits, new services.
- **Tests network segmentation** every night.
- **Correlates** everything into incidents, tags alerts with MITRE ATT&CK techniques, and keeps an audit trail of every change an analyst makes.

Since 2026-09-23 it also runs **broadcast-level attack detection**: it raises a critical alert if an unknown DHCP server appears, if an unknown IPv6 router announces itself, if any device answers a made-up name (the signature of an "LLMNR/NBT-NS poisoning" tool, the most common way an attacker inside a Windows network steals passwords), or if the MAC address behind a gateway or DNS server changes. Transparency note: the poisoning check is an **active, harmless test**: every 10 minutes Kali sends two small name queries (one multicast, one broadcast) for a random nonexistent name on each network. It is what any Windows PC sends when a name does not resolve, so it should not trigger anything on your side. Tell us if you would prefer it limited to some networks and we will do so.

---

## 3. What the SOC cannot see today, and how we know

Kali is a virtual machine with one virtual NIC per VLAN. A switch only delivers to a port the traffic addressed to it, plus broadcast and multicast. So Kali sees:

- **Yes:** broadcasts and multicasts (ARP, DHCP, NetBIOS, mDNS, LLMNR...).
- **No:** the actual conversations between PCs, servers, printers and the internet.

We measured it. In a typical capture window **about 99% of what Zeek observed from other machines was broadcast/multicast, and only 2 TCP connections between other machines were seen at all.** A real attacker moving between two machines, a PC talking to a malware server, a password-spraying run against a server, a large data transfer: none of these would be visible to us today. The detectors exist and are tested; they are starved of data.

Windows-specific blind spot: an attack against a user account (password guessing, a stolen account, a new administrator, a Kerberos attack) is recorded by the domain controller as an event. Kali cannot see those events on the wire, and without them we are blind to the most common attack path in a Windows domain.

---

## 4. What the SOC has already found (please review and act)

These come from scans and tests already run. None was exploited; they are all read-only observations.

### 4.1 No network segmentation: highest priority

The nightly test forces traffic from each VLAN through its real gateway to every other VLAN. **All 30 of 30 possible VLAN pairs are reachable, most recently on 2026-09-23 01:04.** That includes **Guest/Employee Wi-Fi (192.168.8.0/24) reaching Management (10.201.0.0/16) and Wiping (10.21.0.0/16)**. In practice a guest phone can connect to management infrastructure. Networks (Floor, Management, Wiping, Printers, Office, Guest/Employee Wi-Fi) are separated in addressing only, not in enforcement.

**Ask:** review the inter-VLAN rules on the gateways/firewall. At minimum, block Guest/Employee Wi-Fi to Management and Wiping, and restrict access to Management to the machines that administer it. The nightly test will confirm as soon as it changes, and we will send you the result.

### 4.2 Four confirmed vulnerabilities

| Device | VLAN | Problem | Ask |
|---|---|---|---|
| 192.168.7.212 (HP printer) | Office | Anonymous FTP enabled (factory default, JetDirect) | Disable FTP or require credentials |
| 192.168.61.12 (HP printer) | Printers | Same | Same |
| 192.168.61.20 (Zebra printer) | Printers | Same | Same |
| 10.21.0.111 (Dell) | Wiping | New VNC service; most likely the iDRAC console | Confirm what it is; restrict to Management; change default credentials if any |

### 4.3 Windows machines that make the network easier to attack

- **14 machines do not require SMB signing** (including 10.69.0.20, the PXE server). Without it, an attacker who tricks a PC into authenticating can *relay* that authentication to these machines and act as the user. **Ask:** enforce "Microsoft network server: Digitally sign communications (always)" by Group Policy, testing on servers first.
- **4 machines run Windows 10, which stopped receiving security updates on 2025-10-14** (unless the machine has a paid Extended Security Updates contract or is a long-term-servicing edition): 10.69.11.67 (ERA-W4-D041), 10.69.11.94 (DESKTOP-SUKLCOQ), 192.168.7.235 (Lyndsay-PC) and 192.168.7.158 (Chantelle-PC). The scan reads the Windows build over RDP, which identifies the family (Windows 10 2004 through 22H2) but not the exact release, so please confirm the version on each. **Ask:** upgrade to Windows 11 or replace them, or tell us which are exceptions (ESU, LTSC) so we can document them instead of repeating the alert.
- **One Windows 11 machine to check:** 10.69.18.120 (ERA-W4-D025) reports build 22621, which is either 22H2 (out of support) or 23H2 (still supported for Enterprise and Education editions until 2026-11-10; Home and Pro ended 2025-11-11). **Ask:** confirm the release and edition; if it is 22H2, or 23H2 Home/Pro, it needs the feature update to 24H2 or later.
- **LLMNR and NBT-NS** are on by default in Windows, and we have not verified whether they are disabled here. They are what poisoning tools abuse. **Ask:** disable both by Group Policy (Computer Configuration > Administrative Templates > Network > DNS Client > "Turn off multicast name resolution", and disable NetBIOS over TCP/IP in the DHCP scope options or network adapter settings). This removes a whole class of attack.
- **Machines that do not report our domain.** Of the 49 Windows machines that told the scan which domain they belong to, 45 report `era.local`. Four report something else: 10.69.11.94 (DESKTOP-SUKLCOQ) and 192.168.7.222 (IT-Ops-Station) report their own name as the domain, which is how a machine that is *not joined to any domain* appears; 192.168.7.181 (ERA-W4-D013) reports `warehouse.era.local`, which looks like a child domain; and 10.21.0.2 (PartedMagic) is presumably the disk-wiping tool on the Wiping network. **Ask:** confirm which are legitimate and which should be joined to the domain, so they receive Group Policy (SMB signing, LLMNR, updates) like everything else.

---

## 5. Short questions we need answered

1. **Shutdown on 2026-09-21 at 16:01-16:03 (Calgary time):** the Kali VM was shut down and restarted. Was that intentional (maintenance, host reboot)? We want to know whether to treat it as a fault.
2. **Backup destination:** the SOC backs up its own data daily, but only to the same machine. Can IT provide a remote target (an SFTP/SCP location or a file share)? Backups can be encrypted before leaving.
3. **DHCP reservations** for the two administrator PCs that connect to Kali (the wired PC is 10.69.20.178; the Wi-Fi PC's address varies). The firewall on Kali allows them by IP address; if their addresses change, they lose access. A reservation lets us close the broader `10.69.0.0/16` rules. (Remote access over the VPN is unaffected.)
4. **Who owns which device?** About 500 devices are known, and most have no owner recorded. A simple device list (name, owner, purpose) would let us tell "unknown device" from "someone's phone".
5. **Trusted infrastructure:** please confirm the DHCP servers that are meant to exist. We learned 11 from the last days of traffic: 10.69.0.51, 10.69.0.52, 10.21.0.1, 10.201.0.2, 10.201.0.3 (seen only once), 192.168.7.4, 192.168.7.5, 192.168.61.2, 192.168.61.3, 192.168.8.2 and 192.168.8.3; plus one IPv6 router. If any of these is not yours, that is important.
6. **Kali's own firewall:** it currently allows SSH (22) and RDP (3389) from the whole 10.69.0.0/16 network. We plan to narrow this to two PCs once question 3 is done. Tell us if someone else needs access.

---

## 6. The requests in detail

### A. A mirror (SPAN / port-mirroring) port. Highest value

**What:** configure the switch, or the Proxmox virtual switch that hosts `kali2`, to send a copy of traffic to Kali's interface(s). Kali would listen only; it sends nothing to the mirrored traffic.

**Why:** it is what turns the SOC from "sees broadcast" into "sees the network". It enables, using detectors that already exist and are tested: intrusion detection (Suricata rules), scans and lateral movement between internal machines, connections to known-bad addresses and domains, suspicious DNS (tunnelling, random-looking names), unencrypted credentials, unusual data volumes, certificate and protocol anomalies, and the rogue-DHCP and IPv6 checks running on real traffic.

**Where it matters most (in this order):**
1. The **uplink of the core switch / gateway to the internet** (everything going out and coming in).
2. The **Windows servers and domain controllers** (DC1, DC3, file servers, PXE).
3. Inter-VLAN traffic at the gateways.

**Effort and risk:** one configuration line on the switch (or a mirror on the Proxmox bridge). Mirroring does not alter traffic. Watch for: (a) bandwidth: mirroring a busy uplink onto a 1 Gbps virtual NIC can drop packets, so start with the uplink only and tell us the link speed; (b) mirroring is one-way; nothing changes for users.

**What we do with it:** a few hours after it is on, we send you a summary of what is now visible, and a list of surprises (unexpected protocols, devices talking to the internet that should not).

### B. Windows event logs from the domain controllers (DC1, DC3) and, later, servers and endpoints

**What:** forward the Security event log from the domain controllers to a Windows Event Collector (or directly to Kali by an agent such as Winlogbeat or NXLog, or by syslog). Nothing to install on ordinary PCs to begin with.

**Why:** the domain controller records who logged in, from where, who failed, who was added to a privileged group, which accounts were created, and Kerberos ticket requests. These events are how account attacks are detected: password spraying, use of a stolen account, an attacker creating an administrator, or Kerberoasting. No amount of network monitoring shows this.

**Which events (minimum set):** 4624/4625 (logon success/failure), 4648, 4672 (privileged logon), 4720/4722/4724/4738 (account create/enable/change), 4728/4732/4756 (group membership), 4768/4769/4771/4776 (Kerberos/NTLM), 1102 (log cleared). The auditing policy needs "Audit Logon", "Audit Account Management", "Audit Kerberos Authentication Service" and "Audit Directory Service Access" enabled for success and failure.

**Effort:** a Group Policy for the audit settings and a subscription or agent on two servers. **Impact:** negligible load; a few MB per day per DC in a domain of this size.

**Optional, later:** the same for file servers, and Sysmon on a small group of test PCs for process and network telemetry. We are not asking for this now.

### C. DNS, firewall/VPN and Microsoft 365 / Entra logs

| Source | What it lets us detect | Ask |
|---|---|---|
| **DNS server logs** (10.69.0.14, 10.69.0.15) | Malware calling home, DNS tunnelling, access to phishing/known-bad domains. It shows exactly which internal PC asked. | Enable DNS query logging and forward it (or let Kali read it) |
| **Firewall / gateway logs**, including **VPN** | Outside scans and attacks, blocked traffic, VPN logins from unusual countries or times. We already have a country/anonymiser lookup ready. | Forward as syslog to 10.69.0.40 |
| **Microsoft 365 / Entra ID sign-in and audit logs** | Stolen or sprayed passwords against email and cloud apps, impossible-travel logins, new inbox forwarding rules, suspicious OAuth grants, phishing that reached mailboxes. Today our phishing detector has **no mail source at all**. (`O365SYNC` already exists for directory sync.) | An app registration with read-only access to the sign-in, audit and security-alert data (Microsoft Graph: `AuditLog.Read.All`, `SecurityEvents.Read.All`, `Directory.Read.All`). No mailbox access. |

**Effort:** each is a setting or an app registration; the usual cost is a licence tier (sign-in logs need Entra ID P1 or higher for full retention). Tell us what you have and we will size it.

---

## 7. What we will do with each of them, and what we will not

- **We will:** receive, store and analyse the copies; raise alerts; send IT a summary of anything that concerns your systems; keep an audit trail of every SOC action.
- **We will not:** change a configuration, block a device, run exploits, guess passwords or touch a user's mailbox. Phase 1 is detection only; active testing (Phase 2) waits until after the certification and will be scheduled with you before any of it starts.
- **Retention and access:** data stays on the Kali appliance and its encrypted backups. Access to the dashboard is by login. Secrets (alert push topic, API keys) are stored outside the repository with restricted permissions.

## 8. Suggested order

1. **This week (no effort):** answer the six questions; disable anonymous FTP on the three printers; confirm the iDRAC.
2. **Next:** the mirror port (A) and the domain controller audit policy and event forwarding (B). These two make the biggest difference.
3. **Then:** DNS and firewall/VPN logs, Microsoft 365 / Entra logs (C).
4. **In parallel, as time allows:** inter-VLAN rules, SMB signing, disable LLMNR/NBT-NS, unsupported Windows.

We are glad to do a 30-minute walk-through, and can prepare the exact commands or a Group Policy checklist for any item. Please reply with what you can do and when.
