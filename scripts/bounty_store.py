"""
bounty_store.py
SQLite-backed bounty queue. Tracks state from paste → investigation → submission.
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.getenv("DB_PATH", "db/scambusters.db")


def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS bounties (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            bounty_id   TEXT UNIQUE,
            domain      TEXT NOT NULL,
            target_url  TEXT,
            title       TEXT,
            sponsor     TEXT,
            multiplier  REAL DEFAULT 1.0,
            max_claims  INTEGER DEFAULT 1,
            expires_raw TEXT,
            raw_paste   TEXT,
            status      TEXT DEFAULT 'pending',
            created_at  TEXT DEFAULT (datetime('now')),
            started_at  TEXT,
            completed_at TEXT,
            approved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS investigations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            bounty_id       TEXT NOT NULL,
            domain          TEXT NOT NULL,
            urlscan         TEXT,
            whois           TEXT,
            passive_dns     TEXT,
            social_osint    TEXT,
            wallets         TEXT,
            similar_domains TEXT,
            ai_report       TEXT,
            takedown_registrar TEXT,
            takedown_hosting   TEXT,
            submission_package TEXT,
            created_at      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (bounty_id) REFERENCES bounties(bounty_id)
        );
    """)
    conn.commit()
    conn.close()


def add_bounty(parsed: dict) -> int:
    conn = get_conn()
    try:
        conn.execute("""
            INSERT OR IGNORE INTO bounties
            (bounty_id, domain, target_url, title, sponsor, multiplier,
             max_claims, expires_raw, raw_paste, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            parsed.get("bounty_id") or f"manual_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            parsed["domain"],
            parsed.get("target_url"),
            parsed.get("title"),
            parsed.get("sponsor"),
            parsed.get("multiplier", 1.0),
            parsed.get("max_claims", 1),
            parsed.get("expires_raw"),
            parsed.get("raw"),
        ))
        conn.commit()
        row = conn.execute(
            "SELECT id FROM bounties WHERE domain=? ORDER BY id DESC LIMIT 1",
            (parsed["domain"],)
        ).fetchone()
        return row["id"] if row else None
    finally:
        conn.close()


def get_all_bounties() -> list:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM bounties ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_bounty(bounty_id: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM bounties WHERE bounty_id=?", (bounty_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_bounty_by_id(db_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM bounties WHERE id=?", (db_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_status(bounty_id: str, status: str):
    conn = get_conn()
    ts_field = {
        "investigating": "started_at",
        "complete": "completed_at",
        "approved": "approved_at",
    }.get(status)

    if ts_field:
        conn.execute(
            f"UPDATE bounties SET status=?, {ts_field}=datetime('now') WHERE bounty_id=?",
            (status, bounty_id)
        )
    else:
        conn.execute(
            "UPDATE bounties SET status=? WHERE bounty_id=?",
            (status, bounty_id)
        )
    conn.commit()
    conn.close()


def save_investigation(bounty_id: str, domain: str, data: dict):
    conn = get_conn()
    def j(v): return json.dumps(v, default=str) if v else None

    existing = conn.execute(
        "SELECT id FROM investigations WHERE bounty_id=? AND domain=?",
        (bounty_id, domain)
    ).fetchone()

    if existing:
        conn.execute("""
            UPDATE investigations SET
                urlscan=?, whois=?, passive_dns=?, social_osint=?,
                wallets=?, similar_domains=?, ai_report=?,
                takedown_registrar=?, takedown_hosting=?, submission_package=?
            WHERE bounty_id=? AND domain=?
        """, (
            j(data.get("urlscan")), j(data.get("whois")),
            j(data.get("passive_dns")), j(data.get("social_osint")),
            j(data.get("wallets")), j(data.get("similar_domains")),
            j(data.get("ai_report")),
            j(data.get("takedown_registrar")), j(data.get("takedown_hosting")),
            j(data.get("submission_package")),
            bounty_id, domain
        ))
    else:
        conn.execute("""
            INSERT INTO investigations
            (bounty_id, domain, urlscan, whois, passive_dns, social_osint,
             wallets, similar_domains, ai_report, takedown_registrar,
             takedown_hosting, submission_package)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            bounty_id, domain,
            j(data.get("urlscan")), j(data.get("whois")),
            j(data.get("passive_dns")), j(data.get("social_osint")),
            j(data.get("wallets")), j(data.get("similar_domains")),
            j(data.get("ai_report")),
            j(data.get("takedown_registrar")), j(data.get("takedown_hosting")),
            j(data.get("submission_package")),
        ))
    conn.commit()
    conn.close()


def get_investigation(bounty_id: str, domain: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM investigations WHERE bounty_id=? AND domain=?",
        (bounty_id, domain)
    ).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    for field in ["urlscan", "whois", "passive_dns", "social_osint",
                  "wallets", "similar_domains", "ai_report",
                  "takedown_registrar", "takedown_hosting", "submission_package"]:
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    return d


def get_stats() -> dict:
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) as c FROM bounties").fetchone()["c"]
    by_status = conn.execute(
        "SELECT status, COUNT(*) as c FROM bounties GROUP BY status"
    ).fetchall()
    domains_investigated = conn.execute(
        "SELECT COUNT(*) as c FROM investigations"
    ).fetchone()["c"]
    conn.close()
    return {
        "total_bounties": total,
        "by_status": {r["status"]: r["c"] for r in by_status},
        "domains_investigated": domains_investigated,
    }


init_db()
