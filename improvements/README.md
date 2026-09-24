# Improvements

Proposals for future work on the Kali appliance, kept apart from what is built and running. Nothing in
this folder is implemented. The team reviews these proposals and decides which to take on. An accepted
proposal becomes ordinary work in `scripts/`, `kali/` or `deploy/`, and its file records that it was done.

| # | Proposal | Status | Proposed |
| --- | --- | --- | --- |
| 001 | [Self-hosted ntfy server for critical alert pushes](001-self-hosted-ntfy.md) | Proposed | 2026-09-23 |
| 002 | [Off-VM copy of the daily data backup](002-off-vm-data-backup.md) | Proposed | 2026-09-23 |
| 003 | [Automated provisioning of a fresh Kali (packages and sensor configuration)](003-automated-provisioning.md) | Proposed | 2026-09-23 |
| 004 | [Resolve alerts with a note in the platform dashboard, synced back to the Kali](004-resolve-with-note-in-platform.md) | Proposed | 2026-09-23 |

## Adding a proposal

Copy the template below into `NNN-short-name.md`, using the next number, and add a row to the table.

Status is one of: **Proposed** (not reviewed yet), **Accepted** (to be built), **Rejected** (with the
reason), or **Done** (with the commit).

```markdown
# NNN: Title

- **Status:** Proposed
- **Proposed:** YYYY-MM-DD by <name>
- **Effort:** small / medium / large

## Problem
What happens today and why it matters.

## Proposal
What would change.

## What it takes
Code, infrastructure, who needs to be involved.

## Risks and open questions
```
