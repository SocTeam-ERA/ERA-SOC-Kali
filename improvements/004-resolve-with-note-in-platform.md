# 004: Resolve alerts with a note in the platform dashboard, synced back to the Kali

- **Status:** Accepted, in progress. Kali side done 2026-09-24 (7725c10): `GET /api/alerts?status_since=` lists
  status changes with `status_actor` and `status_note`, so the backend can mirror them (docs/API_SPEC_EN.md §5).
  Waiting on ERA-SOC: the backend PATCH with a note, posting it to the Kali, the poller reading status_since,
  and the drawer UI; plus a write key for the backend.
- **Proposed:** 2026-09-23 by Arturo
- **Effort:** medium. The work is mostly in the ERA-SOC repository (backend and frontend).

## Problem

When an analyst closes an alert, the reason is lost:

- **The platform dashboard (ERA-SOC, `SOC-Front`)** has *Acknowledge* and *Resolve* buttons with no note
  field. The backend endpoint `PATCH /api/alerts/{id}` (`SOC-Back/backend/app/main.py`) accepts only
  `status`. It does not store who changed it, when, or why.
- **The status is not sent back to the Kali.** `common/kali_poll.py` pulls alerts one way. An alert
  resolved in the platform stays `open` on the Kali, where the alert aging, weekly digest, correlation and
  the local dashboard all use the Kali's own status.
- **The Kali already supports notes.** `POST /api/alerts/<id>/status` on the Kali API (`scripts/soc_api.py`)
  takes `{"status", "note"}` and records the note and the actor in `data/alert_status_log.jsonl`.
  Nothing in the dashboards calls it.

Example: the AIDE alert expected on 2026-09-24 from moving the ntfy topic should be closed with "ntfy
topic moved to private drop-ins". Today there is no screen where that can be written.

## Proposal

1. **Backend (ERA-SOC):** extend `AlertPatch` with an optional `note`, and store each change with its user,
   time and note in a status history table, or at least in `details`.
2. **Frontend (ERA-SOC):** clicking *Resolve* opens a small text box for the note. It is optional for
   ordinary alerts, and required for critical ones and for AIDE alerts. Show the history in the alert drawer.
3. **Sync back to the Kali:** when the alert came from the Kali (`details.kali_id` is set by `kali_poll`),
   the backend calls the Kali's `POST /api/alerts/<kali_id>/status` with the status and the note. That
   needs a Kali API key with write permission, stored as a backend secret in Dokploy. The Kali records the
   key's user as the actor and never a name sent by the client (`scripts/soc_api.py`), so the backend puts
   the analyst's name in the note, e.g. "[jdoe] ntfy topic moved to private drop-ins".

## What it takes

- Changes in ERA-SOC: an Alembic migration, the endpoint and the drawer UI. The Kali side needs no code
  changes, only a write key issued with `scripts/manage_api_keys.py`.
- Agreement with whoever maintains ERA-SOC, since most of the change is there.

## Risks and open questions

- If the Kali is unreachable when an alert is resolved, the sync must retry later rather than be lost.
- Which side wins if the same alert is changed on both? A reasonable rule is that the latest change wins,
  and both histories record it.
- The platform's scan-worker alerts have no Kali counterpart; they only get steps 1 and 2.
