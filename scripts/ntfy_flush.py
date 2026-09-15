#!/usr/bin/env python3
"""
ntfy_flush.py
-------------
Flushes any pending grouped-critical-alert ntfy summary whose burst window
has closed -- see soc_core.NTFY_BATCH_WINDOW and notify_critical()'s
docstring. Run periodically by soc-ntfy-flush.timer so a summary still goes
out even if nothing else critical happens after a burst ends (otherwise the
last few alerts of a burst that aren't followed by anything would just sit
queued forever, since nothing else would trigger the flush).

Usage:
    python3 ntfy_flush.py
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from soc_core import flush_ntfy_batch  # noqa: E402

if __name__ == "__main__":
    flush_ntfy_batch()
