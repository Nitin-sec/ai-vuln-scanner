"""
db_manager.py — ThreatMap Infra SQLite persistence layer.
All data stays local. No network calls. No server storage.

KEY FIX: insert_triage now saves observation_name, detailed_observation,
         impacted_module, risk_impact — the four AI-generated fields that
         were previously generated but silently dropped.
"""

import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = "threatmap.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DBManager:

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._migrate_schema()
        self._init_schema()

    def _migrate_schema(self) -> None:
        """Auto-add any missing columns without dropping existing data."""
        if not Path(self.db_path).exists():
            return

        conn = sqlite3.connect(self.db_path)
        try:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(triage)")}
        finally:
            conn.close()

        if not columns:
            return

        NEEDED = [
            ("observation_name",     "TEXT"),
            ("detailed_observation", "TEXT"),
            ("impacted_module",      "TEXT"),
            ("risk_impact",          "TEXT"),
        ]
        conn = sqlite3.connect(self.db_path)
        try:
            for col, typ in NEEDED:
                if col not in columns:
                    conn.execute(f"ALTER TABLE triage ADD COLUMN {col} {typ}")
                    print(f"[DB] Auto-migrated: added triage.{col}")
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    target       TEXT    NOT NULL,
                    scan_mode    TEXT    NOT NULL,
                    max_workers  INTEGER DEFAULT 2,
                    started_at   TEXT    NOT NULL,
                    completed_at TEXT,
                    status       TEXT    DEFAULT 'running'
                );

                CREATE TABLE IF NOT EXISTS hosts (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id       INTEGER NOT NULL,
                    url           TEXT    NOT NULL,
                    domain        TEXT    NOT NULL,
                    discovered_at TEXT    NOT NULL,
                    UNIQUE(scan_id, url),
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );

                CREATE TABLE IF NOT EXISTS open_ports (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port    TEXT    NOT NULL,
                    state   TEXT    NOT NULL,
                    service TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );

                CREATE TABLE IF NOT EXISTS screenshots (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id         INTEGER NOT NULL,
                    url             TEXT    NOT NULL,
                    screenshot_path TEXT,
                    http_status     INTEGER,
                    page_title      TEXT,
                    eyewitness_dir  TEXT,
                    captured_at     TEXT    NOT NULL,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );

                CREATE TABLE IF NOT EXISTS terminal_logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     INTEGER NOT NULL,
                    command     TEXT    NOT NULL,
                    log_path    TEXT    NOT NULL,
                    recorded_at TEXT    NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );

                CREATE TABLE IF NOT EXISTS triage (
                    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id                   INTEGER,
                    host                      TEXT    NOT NULL,
                    port                      TEXT    NOT NULL,
                    service                   TEXT,
                    severity                  TEXT    NOT NULL,
                    priority_rank             INTEGER DEFAULT 5,
                    cvss_score                REAL    DEFAULT 0.0,
                    actively_exploited        INTEGER DEFAULT 0,
                    observation_name          TEXT,
                    detailed_observation      TEXT,
                    impacted_module           TEXT,
                    risk_impact               TEXT,
                    risk_summary              TEXT,
                    remediation               TEXT,
                    business_impact           TEXT,
                    false_positive_likelihood TEXT,
                    attack_scenario           TEXT,
                    triage_method             TEXT    DEFAULT 'rule_based',
                    ai_enhanced               INTEGER DEFAULT 0,
                    triaged_at                TEXT    NOT NULL,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );
            """)

    # ── Scans ─────────────────────────────────────────────────────────────

    def init_scan(self, target: str, scan_mode: str, max_workers: int) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, scan_mode, max_workers, started_at) "
                "VALUES (?,?,?,?)",
                (target, scan_mode, max_workers, _now()),
            )
            return cur.lastrowid

    def complete_scan(self, scan_id: int) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, status='completed' WHERE id=?",
                (_now(), scan_id),
            )

    def fail_scan(self, scan_id: int, reason: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, status=? WHERE id=?",
                (_now(), f"failed: {reason}", scan_id),
            )

    # ── Hosts ─────────────────────────────────────────────────────────────

    def upsert_host(self, scan_id: int, url: str, domain: str) -> int:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO hosts (scan_id, url, domain, discovered_at) "
                "VALUES (?,?,?,?) ON CONFLICT(scan_id, url) DO NOTHING",
                (scan_id, url, domain, _now()),
            )
            row = conn.execute(
                "SELECT id FROM hosts WHERE scan_id=? AND url=?",
                (scan_id, url),
            ).fetchone()
            return row["id"]

    def insert_ports(self, host_id: int, ports: list[dict]) -> None:
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO open_ports (host_id, port, state, service) VALUES (?,?,?,?)",
                [(host_id, p["port"], p.get("state", "open"), p.get("service", "unknown"))
                 for p in ports],
            )

    # ── Screenshots ───────────────────────────────────────────────────────

    def upsert_screenshot(self, host_id, url, screenshot_path,
                          eyewitness_dir=None, http_status=None,
                          page_title=None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO screenshots "
                "(host_id, url, screenshot_path, eyewitness_dir, "
                "http_status, page_title, captured_at) VALUES (?,?,?,?,?,?,?)",
                (host_id, url, screenshot_path, eyewitness_dir,
                 http_status, page_title, _now()),
            )
            return cur.lastrowid

    def get_screenshots_for_scan(self, scan_id: int):
        with self._conn() as conn:
            return conn.execute(
                "SELECT s.url, s.screenshot_path, s.http_status, "
                "s.page_title, s.captured_at "
                "FROM screenshots s JOIN hosts h ON s.host_id=h.id "
                "WHERE h.scan_id=? ORDER BY s.captured_at",
                (scan_id,),
            ).fetchall()

    # ── Terminal logs ─────────────────────────────────────────────────────

    def insert_terminal_log(self, scan_id, command, log_path) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO terminal_logs (scan_id, command, log_path, recorded_at) "
                "VALUES (?,?,?,?)",
                (scan_id, command, log_path, _now()),
            )
            return cur.lastrowid

    def get_terminal_logs_for_scan(self, scan_id: int):
        with self._conn() as conn:
            return conn.execute(
                "SELECT command, log_path, recorded_at FROM terminal_logs "
                "WHERE scan_id=? ORDER BY recorded_at",
                (scan_id,),
            ).fetchall()

    # ── Triage ────────────────────────────────────────────────────────────

    def clear_triage(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM triage")

    def delete_triage_by_scan(self, scan_id: int) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                DELETE FROM triage
                WHERE host_id IN (
                    SELECT id FROM hosts WHERE scan_id=?
                )
                """,
                (scan_id,),
            )

    def insert_triage(self, record: dict) -> int:
        """
        Save ALL triage fields — including the four AI-generated columns.
        Previously observation_name / detailed_observation / impacted_module /
        risk_impact were generated by the AI engine but never written to DB.
        This is the fix.
        """
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO triage (
                    host_id, host, port, service,
                    severity, priority_rank, cvss_score, actively_exploited,
                    observation_name, detailed_observation,
                    impacted_module,  risk_impact,
                    risk_summary, remediation, business_impact,
                    false_positive_likelihood, attack_scenario,
                    triage_method, ai_enhanced, triaged_at
                ) VALUES (?,?,?,?,  ?,?,?,?,  ?,?,  ?,?,  ?,?,?,  ?,?,  ?,?,?)
                """,
                (
                    record.get("host_id"),
                    record.get("host", ""),
                    record.get("port", ""),
                    record.get("service"),
                    # severity
                    record.get("severity", "Info"),
                    record.get("priority_rank", 5),
                    record.get("cvss_score", 0.0),
                    int(record.get("actively_exploited", False)),
                    # AI fields — THE FIX
                    record.get("observation_name"),
                    record.get("detailed_observation"),
                    record.get("impacted_module"),
                    record.get("risk_impact"),
                    # rule-based fields
                    record.get("risk_summary"),
                    record.get("remediation"),
                    record.get("business_impact"),
                    record.get("false_positive_likelihood"),
                    record.get("attack_scenario"),
                    # meta
                    record.get("triage_method", "rule_based"),
                    int(record.get("ai_enhanced", False)),
                    _now(),
                ),
            )
            return cur.lastrowid

    def get_all_triage(self):
        with self._conn() as conn:
            return conn.execute(
                """
                SELECT t.*
                FROM   triage t
                ORDER BY
                    t.priority_rank ASC,
                    CASE t.severity
                        WHEN 'Critical' THEN 1 WHEN 'High'   THEN 2
                        WHEN 'Medium'   THEN 3 WHEN 'Low'    THEN 4
                        ELSE 5
                    END ASC
                """
            ).fetchall()

    def get_triage_by_scan(self, scan_id: int):
        with self._conn() as conn:
            return conn.execute(
                """
                SELECT t.*
                FROM triage t
                JOIN hosts h ON h.id = t.host_id
                WHERE h.scan_id=?
                ORDER BY
                    t.priority_rank ASC,
                    CASE t.severity
                        WHEN 'Critical' THEN 1 WHEN 'High'   THEN 2
                        WHEN 'Medium'   THEN 3 WHEN 'Low'    THEN 4
                        ELSE 5
                    END ASC
                """,
                (scan_id,),
            ).fetchall()

    # ── Lightweight evidence summary ──────────────────────────────────────

    def generate_evidence_report(self, scan_id: int, output_path: str) -> None:
        screenshots = self.get_screenshots_for_scan(scan_id)
        with self._conn() as conn:
            scan_row = conn.execute(
                "SELECT target, started_at, completed_at FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()

        target    = scan_row["target"] if scan_row else "unknown"
        started   = scan_row["started_at"] if scan_row else ""
        completed = (scan_row["completed_at"] or "In Progress") if scan_row else ""

        rows_html = ""
        for row in screenshots:
            rows_html += (
                f"<tr><td>{_esc(row['url'])}</td>"
                f"<td>{row['http_status'] or '—'}</td>"
                f"<td>{_esc(row['page_title'] or '—')}</td>"
                f"<td>{row['captured_at']}</td></tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ThreatMap Evidence — {_esc(target)}</title>
<style>
body{{font-family:Arial,sans-serif;background:#fff;color:#222;padding:2rem;max-width:1100px;margin:auto}}
h1{{color:#C0392B;border-bottom:3px solid #C0392B;padding-bottom:.5rem}}
table{{width:100%;border-collapse:collapse;margin-top:1rem;font-size:.9rem}}
th{{background:#2C3E50;color:#fff;padding:8px 12px;text-align:left}}
td{{padding:8px 12px;border-bottom:1px solid #ddd}}tr:hover td{{background:#f9f9f9}}
</style></head><body>
<h1>ThreatMap — HTTP Evidence</h1>
<p><strong>Target:</strong> {_esc(target)} &nbsp;|&nbsp;
<strong>Started:</strong> {started} &nbsp;|&nbsp;
<strong>Completed:</strong> {completed}</p>
<table><thead>
<tr><th>URL</th><th>HTTP Status</th><th>Page Title</th><th>Captured</th></tr>
</thead><tbody>
{rows_html or "<tr><td colspan='4'>No HTTP evidence captured.</td></tr>"}
</tbody></table></body></html>"""

        Path(output_path).write_text(html, encoding="utf-8")
        print(f"    [DB] Evidence summary → {output_path}")


def _esc(s) -> str:
    if not s:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
