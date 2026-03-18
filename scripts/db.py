"""
db.py — PostgreSQL database layer for ScamBusters Agent v2
Replaces SQLite bounty_store.py with production-grade Postgres.
"""

import os
import json
import psycopg2
import psycopg2.extras
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/scambusters")


def get_conn():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS bounties (
            id              SERIAL PRIMARY KEY,
            bounty_id       TEXT UNIQUE NOT NULL,
            domain          TEXT NOT NULL,
            target_url      TEXT,
            title           TEXT,
            sponsor         TEXT,
            multiplier      FLOAT DEFAULT 1.0,
            max_claims      INT DEFAULT 1,
            expires_raw     TEXT,
            raw_paste       TEXT,
            status          TEXT DEFAULT 'pending',
            risk_score      INT DEFAULT 0,
            risk_level      TEXT DEFAULT 'unknown',
            created_at      TIMESTAMPTZ DEFAULT NOW(),
            started_at      TIMESTAMPTZ,
            completed_at    TIMESTAMPTZ,
            approved_at     TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS investigations (
            id                  SERIAL PRIMARY KEY,
            bounty_id           TEXT NOT NULL REFERENCES bounties(bounty_id),
            domain              TEXT NOT NULL,
            urlscan             JSONB,
            whois               JSONB,
            passive_dns         JSONB,
            social_osint        JSONB,
            cert_osint          JSONB,
            shodan              JSONB,
            virustotal          JSONB,
            blockchain          JSONB,
            similar_domains     JSONB,
            ai_report           JSONB,
            risk_score          INT DEFAULT 0,
            risk_level          TEXT DEFAULT 'unknown',
            risk_breakdown      JSONB,
            takedown_registrar  JSONB,
            takedown_hosting    JSONB,
            submission_package  JSONB,
            le_package          JSONB,
            created_at          TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(bounty_id, domain)
        );

        CREATE TABLE IF NOT EXISTS wallets (
            id              SERIAL PRIMARY KEY,
            domain          TEXT NOT NULL,
            bounty_id       TEXT,
            currency        TEXT NOT NULL,
            address         TEXT NOT NULL,
            tx_count        INT DEFAULT 0,
            total_received  FLOAT DEFAULT 0,
            total_received_usd FLOAT DEFAULT 0,
            first_seen      TIMESTAMPTZ,
            last_seen       TIMESTAMPTZ,
            is_active       BOOLEAN DEFAULT FALSE,
            raw_data        JSONB,
            created_at      TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(address, currency)
        );

        CREATE TABLE IF NOT EXISTS threat_actors (
            id              SERIAL PRIMARY KEY,
            soa_email       TEXT UNIQUE,
            registrant_org  TEXT,
            registrant_name TEXT,
            domain_count    INT DEFAULT 0,
            wallet_count    INT DEFAULT 0,
            total_stolen_usd FLOAT DEFAULT 0,
            known_domains   JSONB DEFAULT '[]',
            known_ips       JSONB DEFAULT '[]',
            registrars_used JSONB DEFAULT '[]',
            risk_level      TEXT DEFAULT 'unknown',
            first_seen      TIMESTAMPTZ,
            last_seen       TIMESTAMPTZ,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS network_edges (
            id          SERIAL PRIMARY KEY,
            source      TEXT NOT NULL,
            target      TEXT NOT NULL,
            edge_type   TEXT NOT NULL,
            weight      FLOAT DEFAULT 1.0,
            metadata    JSONB,
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(source, target, edge_type)
        );

        CREATE TABLE IF NOT EXISTS domain_intel (
            id              SERIAL PRIMARY KEY,
            domain          TEXT UNIQUE NOT NULL,
            primary_ip      TEXT,
            asn             TEXT,
            asn_name        TEXT,
            country         TEXT,
            registrar       TEXT,
            creation_date   TEXT,
            soa_email       TEXT,
            template_family TEXT,
            clone_count     INT DEFAULT 0,
            subdomains      JSONB DEFAULT '[]',
            open_ports      JSONB DEFAULT '[]',
            vt_score        INT DEFAULT 0,
            risk_score      INT DEFAULT 0,
            risk_level      TEXT DEFAULT 'unknown',
            takedown_status TEXT DEFAULT 'active',
            last_seen       TIMESTAMPTZ,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_bounties_status ON bounties(status);
        CREATE INDEX IF NOT EXISTS idx_bounties_domain ON bounties(domain);
        CREATE INDEX IF NOT EXISTS idx_wallets_address ON wallets(address);
        CREATE INDEX IF NOT EXISTS idx_wallets_domain ON wallets(domain);
        CREATE INDEX IF NOT EXISTS idx_threat_actors_soa ON threat_actors(soa_email);
        CREATE INDEX IF NOT EXISTS idx_network_edges_source ON network_edges(source);
        CREATE INDEX IF NOT EXISTS idx_domain_intel_domain ON domain_intel(domain);
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("[db] Schema initialized.")


# ── Bounty operations ─────────────────────────────────────────────────────────

def add_bounty(parsed: dict) -> str:
    conn = get_conn()
    cur = conn.cursor()
    bounty_id = parsed.get("bounty_id") or f"manual_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    try:
        cur.execute("""
            INSERT INTO bounties
            (bounty_id, domain, target_url, title, sponsor, multiplier,
             max_claims, expires_raw, raw_paste, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
            ON CONFLICT (bounty_id) DO NOTHING
        """, (
            bounty_id, parsed["domain"], parsed.get("target_url"),
            parsed.get("title"), parsed.get("sponsor"),
            parsed.get("multiplier", 1.0), parsed.get("max_claims", 1),
            parsed.get("expires_raw"), parsed.get("raw"),
        ))
        conn.commit()
        return bounty_id
    finally:
        cur.close()
        conn.close()


def get_all_bounties() -> list:
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM bounties ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]


def get_bounty(bounty_id: str) -> dict | None:
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM bounties WHERE bounty_id=%s", (bounty_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return dict(row) if row else None


def update_status(bounty_id: str, status: str):
    conn = get_conn()
    cur = conn.cursor()
    ts_map = {
        "investigating": "started_at",
        "complete": "completed_at",
        "approved": "approved_at",
    }
    ts_field = ts_map.get(status)
    if ts_field:
        cur.execute(
            f"UPDATE bounties SET status=%s, {ts_field}=NOW() WHERE bounty_id=%s",
            (status, bounty_id)
        )
    else:
        cur.execute("UPDATE bounties SET status=%s WHERE bounty_id=%s", (status, bounty_id))
    conn.commit()
    cur.close()
    conn.close()


def update_bounty_risk(bounty_id: str, score: int, level: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE bounties SET risk_score=%s, risk_level=%s WHERE bounty_id=%s",
        (score, level, bounty_id)
    )
    conn.commit()
    cur.close()
    conn.close()


# ── Investigation operations ──────────────────────────────────────────────────

def save_investigation(bounty_id: str, domain: str, data: dict):
    conn = get_conn()
    cur = conn.cursor()

    def j(v):
        return json.dumps(v, default=str) if v is not None else None

    cur.execute("""
        INSERT INTO investigations
        (bounty_id, domain, urlscan, whois, passive_dns, social_osint,
         cert_osint, shodan, virustotal, blockchain, similar_domains,
         ai_report, risk_score, risk_level, risk_breakdown,
         takedown_registrar, takedown_hosting, submission_package, le_package)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (bounty_id, domain) DO UPDATE SET
            urlscan=EXCLUDED.urlscan, whois=EXCLUDED.whois,
            passive_dns=EXCLUDED.passive_dns, social_osint=EXCLUDED.social_osint,
            cert_osint=EXCLUDED.cert_osint, shodan=EXCLUDED.shodan,
            virustotal=EXCLUDED.virustotal, blockchain=EXCLUDED.blockchain,
            similar_domains=EXCLUDED.similar_domains, ai_report=EXCLUDED.ai_report,
            risk_score=EXCLUDED.risk_score, risk_level=EXCLUDED.risk_level,
            risk_breakdown=EXCLUDED.risk_breakdown,
            takedown_registrar=EXCLUDED.takedown_registrar,
            takedown_hosting=EXCLUDED.takedown_hosting,
            submission_package=EXCLUDED.submission_package,
            le_package=EXCLUDED.le_package
    """, (
        bounty_id, domain,
        j(data.get("urlscan")), j(data.get("whois")),
        j(data.get("passive_dns")), j(data.get("social_osint")),
        j(data.get("cert_osint")), j(data.get("shodan")),
        j(data.get("virustotal")), j(data.get("blockchain")),
        j(data.get("similar_domains")), j(data.get("ai_report")),
        data.get("risk_score", 0), data.get("risk_level", "unknown"),
        j(data.get("risk_breakdown")),
        j(data.get("takedown_registrar")), j(data.get("takedown_hosting")),
        j(data.get("submission_package")), j(data.get("le_package")),
    ))
    conn.commit()
    cur.close()
    conn.close()


def get_investigation(bounty_id: str, domain: str) -> dict | None:
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM investigations WHERE bounty_id=%s AND domain=%s",
        (bounty_id, domain)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return dict(row) if row else None


# ── Wallet operations ─────────────────────────────────────────────────────────

def upsert_wallet(domain: str, bounty_id: str, currency: str,
                  address: str, blockchain_data: dict):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO wallets
        (domain, bounty_id, currency, address, tx_count, total_received,
         total_received_usd, first_seen, last_seen, is_active, raw_data)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (address, currency) DO UPDATE SET
            tx_count=EXCLUDED.tx_count,
            total_received=EXCLUDED.total_received,
            total_received_usd=EXCLUDED.total_received_usd,
            last_seen=EXCLUDED.last_seen,
            is_active=EXCLUDED.is_active,
            raw_data=EXCLUDED.raw_data
    """, (
        domain, bounty_id, currency, address,
        blockchain_data.get("tx_count", 0),
        blockchain_data.get("total_received", 0),
        blockchain_data.get("total_received_usd", 0),
        blockchain_data.get("first_seen"),
        blockchain_data.get("last_seen"),
        blockchain_data.get("is_active", False),
        json.dumps(blockchain_data, default=str),
    ))
    conn.commit()
    cur.close()
    conn.close()


def get_wallets_for_domain(domain: str) -> list:
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM wallets WHERE domain=%s ORDER BY total_received_usd DESC",
        (domain,)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]


# ── Network graph operations ──────────────────────────────────────────────────

def add_edge(source: str, target: str, edge_type: str,
             weight: float = 1.0, metadata: dict = None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO network_edges (source, target, edge_type, weight, metadata)
        VALUES (%s,%s,%s,%s,%s)
        ON CONFLICT (source, target, edge_type) DO UPDATE SET
            weight=EXCLUDED.weight, metadata=EXCLUDED.metadata
    """, (source, target, edge_type, weight, json.dumps(metadata or {})))
    conn.commit()
    cur.close()
    conn.close()


def get_graph_for_domain(domain: str, depth: int = 2) -> dict:
    """Return nodes and edges for D3 force graph centered on domain."""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    visited = set()
    queue = [domain]
    all_edges = []

    for _ in range(depth):
        if not queue:
            break
        placeholders = ",".join(["%s"] * len(queue))
        cur.execute(f"""
            SELECT * FROM network_edges
            WHERE source IN ({placeholders}) OR target IN ({placeholders})
        """, queue + queue)
        edges = cur.fetchall()
        all_edges.extend([dict(e) for e in edges])
        visited.update(queue)
        queue = []
        for e in edges:
            if e["source"] not in visited:
                queue.append(e["source"])
            if e["target"] not in visited:
                queue.append(e["target"])

    cur.close()
    conn.close()

    nodes = {}
    for e in all_edges:
        for n in [e["source"], e["target"]]:
            if n not in nodes:
                node_type = "domain" if "." in n else (
                    "ip" if n.replace(".", "").isdigit() else (
                        "wallet" if len(n) > 30 else "actor"
                    )
                )
                nodes[n] = {"id": n, "type": node_type, "weight": 1}
            nodes[n]["weight"] += 1

    return {
        "nodes": list(nodes.values()),
        "edges": [{"source": e["source"], "target": e["target"],
                   "type": e["edge_type"], "weight": e["weight"]}
                  for e in all_edges],
    }


# ── Public stats ──────────────────────────────────────────────────────────────

def get_public_stats() -> dict:
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("SELECT COUNT(*) as total FROM bounties")
    total = cur.fetchone()["total"]

    cur.execute("SELECT status, COUNT(*) as c FROM bounties GROUP BY status")
    by_status = {r["status"]: r["c"] for r in cur.fetchall()}

    cur.execute("SELECT COUNT(*) as total FROM wallets")
    wallet_count = cur.fetchone()["total"]

    cur.execute("SELECT COALESCE(SUM(total_received_usd),0) as total FROM wallets")
    total_stolen = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) as total FROM threat_actors")
    actor_count = cur.fetchone()["total"]

    cur.execute("""
        SELECT domain, risk_score, risk_level, created_at
        FROM bounties
        WHERE status IN ('complete','approved')
        ORDER BY created_at DESC LIMIT 10
    """)
    recent = [dict(r) for r in cur.fetchall()]

    cur.close()
    conn.close()

    return {
        "total_bounties": total,
        "by_status": by_status,
        "wallet_count": wallet_count,
        "total_stolen_usd": float(total_stolen),
        "threat_actors": actor_count,
        "recent_investigations": recent,
    }


def get_stats() -> dict:
    return get_public_stats()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
