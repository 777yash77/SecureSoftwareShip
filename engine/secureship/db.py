from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from secureship.models import Finding, ScanResult, ScanSummary, Severity, ShipStatus


DEFAULT_DB_DIR = Path.home() / ".secureship"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "history.db"


class HistoryDB:
    """Persistent SQLite storage for SecureShip scan history and trend analytics."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    security_score INTEGER NOT NULL,
                    ship_status TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    lines_scanned INTEGER NOT NULL,
                    scan_duration_ms REAL NOT NULL,
                    summary_json TEXT NOT NULL,
                    findings_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC)"
            )
            conn.commit()

    def save_scan(self, result: ScanResult) -> None:
        try:
            summary = result.summary
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scans (
                        scan_id, timestamp, target_path, security_score, ship_status,
                        total_findings, critical_count, high_count, medium_count, low_count,
                        files_scanned, lines_scanned, scan_duration_ms, summary_json, findings_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scan_id,
                        result.timestamp,
                        result.target_path,
                        summary.security_score,
                        summary.ship_status.value if hasattr(summary.ship_status, "value") else str(summary.ship_status),
                        summary.total_findings,
                        summary.critical_count,
                        summary.high_count,
                        summary.medium_count,
                        summary.low_count,
                        summary.files_scanned,
                        summary.lines_scanned,
                        summary.scan_duration_ms,
                        summary.model_dump_json(),
                        json.dumps([f.model_dump() for f in result.findings]),
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def get_recent_scans(self, limit: int = 50) -> List[ScanResult]:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT scan_id, timestamp, target_path, summary_json, findings_json FROM scans ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                )
                rows = cursor.fetchall()
                results: List[ScanResult] = []
                for r in rows:
                    try:
                        summary_data = json.loads(r["summary_json"])
                        findings_data = json.loads(r["findings_json"])
                        summary = ScanSummary(**summary_data)
                        findings = [Finding(**f) for f in findings_data]
                        results.append(
                            ScanResult(
                                scan_id=r["scan_id"],
                                timestamp=r["timestamp"],
                                target_path=r["target_path"],
                                summary=summary,
                                findings=findings,
                            )
                        )
                    except Exception:
                        continue
                return results
        except Exception:
            return []

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT scan_id, timestamp, target_path, summary_json, findings_json FROM scans WHERE scan_id = ?",
                    (scan_id,),
                )
                r = cursor.fetchone()
                if not r:
                    return None
                try:
                    summary = ScanSummary(**json.loads(r["summary_json"]))
                    findings = [Finding(**f) for f in json.loads(r["findings_json"])]
                    return ScanResult(
                        scan_id=r["scan_id"],
                        timestamp=r["timestamp"],
                        target_path=r["target_path"],
                        summary=summary,
                        findings=findings,
                    )
                except Exception:
                    return None
        except Exception:
            return None

    def get_score_trend(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns simplified chronological trend data for graphing."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT scan_id, timestamp, target_path, security_score, ship_status,
                           critical_count, high_count, total_findings
                    FROM scans ORDER BY timestamp ASC LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []


_default_db = HistoryDB()


def save_scan(result: ScanResult) -> None:
    _default_db.save_scan(result)


def get_recent_scans(limit: int = 50) -> List[ScanResult]:
    return _default_db.get_recent_scans(limit)


def get_scan(scan_id: str) -> Optional[ScanResult]:
    return _default_db.get_scan(scan_id)


def get_score_trend(limit: int = 20) -> List[Dict[str, Any]]:
    return _default_db.get_score_trend(limit)

