"""
db_patch_v2.py — ThreatMap Infra — adds all missing triage columns + fixes get_all_triage

Run once:   python3 db_patch_v2.py

Safe to run multiple times.
"""

import sqlite3
from pathlib import Path

DB_PATH = "threatmap.db"

NEW_COLS = [
    ("observation_name",     "TEXT"),
    ("detailed_observation", "TEXT"),
    ("impacted_module",      "TEXT"),
    ("risk_impact",          "TEXT"),
]


def patch(path=DB_PATH):
    if not Path(path).exists():
        print(f"[!] {path} not found — run a scan first.")
        return

    conn = sqlite3.connect(path)
    existing = {r[1] for r in conn.execute("PRAGMA table_info(triage)")}

    added = []
    for col, typ in NEW_COLS:
        if col not in existing:
            conn.execute(f"ALTER TABLE triage ADD COLUMN {col} {typ}")
            added.append(col)
            print(f"  [+] Added: triage.{col}")
        else:
            print(f"  [=] Already exists: triage.{col}")

    conn.commit()
    conn.close()

    if added:
        print(f"\nMigration complete. {len(added)} column(s) added.")
        print("Delete threatmap.db and re-run a scan to get fresh data,")
        print("or re-run a new scan — the columns will populate automatically.")
    else:
        print("\nDatabase schema is already up to date.")


if __name__ == "__main__":
    patch()
