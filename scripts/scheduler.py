"""
scheduler.py — Proactive Discovery Engine
Runs on a schedule to find new scam sites without waiting for bounties.
Sources:
1. HYIP monitoring sites (scrape)
2. URLScan cryptoscam tag (API)
3. I4G known domain list (future)

Can be run manually or via cron / Railway cron job.
"""

import os
import time
import random
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def run_discovery_cycle(max_domains: int = 50) -> list:
    """
    Run a full discovery cycle and return new domains found.
    Skips domains already in the database.
    """
    from scripts.discover_scams import discover_scam_domains
    from scripts.db import get_conn

    print(f"\n[{datetime.utcnow().isoformat()}] Starting discovery cycle...")

    # Find all known domains to skip
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT domain FROM bounties UNION SELECT domain FROM domain_intel")
    known = {row[0] for row in cur.fetchall()}
    cur.close()
    conn.close()

    # Discover new domains
    urlscan_key = os.getenv("URLSCAN_API_KEY", "")
    all_domains = discover_scam_domains(
        max_domains=max_domains,
        urlscan_api_key=urlscan_key
    )

    new_domains = [d for d in all_domains if d not in known]
    print(f"  Found {len(all_domains)} domains, {len(new_domains)} new")

    return new_domains


def auto_queue_investigations(domains: list) -> int:
    """
    Queue discovered domains as unsponsored investigations.
    Creates bounty entries with sponsor='auto-discovery'.
    """
    from scripts.db import add_bounty
    queued = 0

    for domain in domains:
        parsed = {
            "bounty_id": f"autodiscovery_{domain.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d')}",
            "domain": domain,
            "target_url": f"https://{domain}",
            "title": f"Auto-discovered: {domain}",
            "sponsor": "auto-discovery",
            "multiplier": 1.0,
            "max_claims": 1,
            "raw": f"Auto-discovered via HYIP monitor scrape on {datetime.utcnow().date()}",
        }
        try:
            add_bounty(parsed)
            queued += 1
        except Exception as e:
            print(f"  [!] Failed to queue {domain}: {e}")

    print(f"  Queued {queued} new domains for investigation")
    return queued


def run_full_cycle(max_domains: int = 20, auto_investigate: bool = False):
    """
    Full discovery → queue → optionally investigate cycle.
    Set auto_investigate=True to immediately run the pipeline on new finds.
    """
    new_domains = run_discovery_cycle(max_domains)

    if not new_domains:
        print("  No new domains found this cycle.")
        return

    queued = auto_queue_investigations(new_domains)

    if auto_investigate and queued > 0:
        from scripts.db import get_bounty
        from agent import run_investigation
        print(f"\n  Auto-investigating {min(queued, 5)} domains...")

        for domain in new_domains[:5]:
            bounty_id = f"autodiscovery_{domain.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d')}"
            bounty = get_bounty(bounty_id)
            if bounty:
                print(f"  Investigating: {domain}")
                try:
                    run_investigation(bounty)
                    time.sleep(random.uniform(5, 10))
                except Exception as e:
                    print(f"  [!] Investigation failed for {domain}: {e}")

    print(f"\n[{datetime.utcnow().isoformat()}] Discovery cycle complete.")
    return new_domains


if __name__ == "__main__":
    import sys
    auto = "--auto" in sys.argv
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    run_full_cycle(max_domains=limit, auto_investigate=auto)
