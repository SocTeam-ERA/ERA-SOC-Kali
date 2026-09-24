# 002: Off-VM copy of the daily data backup

- **Status:** Proposed
- **Proposed:** 2026-09-23 by Arturo
- **Effort:** small (the script already supports it; the work is a destination from IT)

## Problem

`kali/backup_data.sh` runs every night at 03:17 and archives `data/` and `config/`: alert history,
incidents, the asset inventory with owners and notes, suppressions and scan state. Each archive is about
4.2 MB, and the newest 14 are kept.

They are kept only in `~/soc-backups` **on the same VM**. If the VM is lost, the backups are lost with it.
The code and the systemd configuration are now safe in GitHub, but the SOC's history is not.
`data/` is deliberately not in git: it changes constantly and holds internal findings.

## Proposal

Use the remote copy that `backup_data.sh` already supports:

- `SOC_BACKUP_REMOTE=user@host:/path` copies each archive and its `.sha256` with rsync over SSH after the
  local backup succeeds.
- `SOC_BACKUP_SSH_KEY=<path>` is a dedicated key for that copy.
- `SOC_BACKUP_GPG_RECIPIENT=<key id>` encrypts the archive before it leaves the VM, so the destination
  never sees internal IPs or findings in clear.

The steps:

1. IT provides a destination outside this VM's host: a Linux server or NAS reachable over SSH, with a
   folder and a restricted account (rsync only, ideally with `rrsync`).
2. Create a dedicated SSH key and a GPG key pair for backups. The GPG private key goes only in the team's
   password vault, never on the Kali: then a compromised Kali cannot read old backups.
3. Add the three variables to the backup line in `deploy/crontab.txt`, and run `deploy/install_all.sh`.
4. Test a restore from the remote copy: `gpg --decrypt`, then `kali/backup_data.sh --restore <file> <dir>`.

The backup status (`data/backup_status.json`) already records `remote: ok | failed`, so a failing remote
copy can be alerted on by the existing source-health check.

## What it takes

- A destination and an account from IT. **This is the only blocker.**
- About an hour of setup, plus the restore test.

## Risks and open questions

- The crontab line would hold the destination and key paths, not secrets, so it can stay in git.
- Retention on the destination is not handled by the script: IT or a cron job there must prune old files.
- If the GPG private key is lost, the remote backups cannot be read. It needs to be stored in the vault
  with a second copy.
