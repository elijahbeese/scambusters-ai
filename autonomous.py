"""
autonomous.py — ScamBusters Autonomous Investigation Engine
Runs continuously, discovering and investigating scam domains
without any human input.

Flow:
1. Discover new domains from all sources
2. Filter out already-investigated domains
3. Score domains by likely value (active, has wallets, high IP cluster)
4. Auto-investigate in priority order
5. Flag high-value findings for submission
6. Repeat on schedule

Run modes:
  python3 autonomous.py              # Run once, investigate top 10
  python3 autonomous.py --continuous # Run forever (every 4 hours)
  python3 autonomous.py --discover   # Discovery only, no investigation
  python3 autonomous.py --count 25   # Investigate top 25
"""

import os
import sys
import time
import json
import argparse
import threading
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()


def get_known_domains() -> set:
    """Get all domains already in the database."""
    try:
        from scripts.db import get_conn
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT domain FROM bounties UNION SELECT domain FROM domain_intel")
        domains = {row[0] for row in cur.fetchall()}
        cur.close()
        conn.close()
        return domains
    except Exception as e:
        print(f"  [auto] DB error getting known domains: {e}")
        return set()


def score_domain(domain: str) -> int:
    """
    Score a domain 0-100 for investigation priority.
    Higher = more likely to be an active, valuable target.
    """
    score = 0
    domain_lower = domain.lower()

    # High-value keywords
    high_value = ["stake", "invest", "capital", "wealth", "profit",
                  "yield", "fund", "trade", "signal", "earn", "mining"]
    medium_value = ["crypto", "coin", "token", "finance", "market",
                    "asset", "defi", "bitcoin", "eth"]

    for kw in high_value:
        if kw in domain_lower:
            score += 15
            break

    for kw in medium_value:
        if kw in domain_lower:
            score += 8
            break

    # Suspicious TLDs commonly used by scammers
    suspicious_tlds = [".xyz", ".online", ".site", ".store", ".cc",
                       ".pro", ".app", ".io", ".net", ".org"]
    common_tlds = [".com"]

    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            score += 10
            break

    for tld in common_tlds:
        if domain_lower.endswith(tld):
            score += 5
            break

    # Length heuristic (scam domains tend to be longer)
    if len(domain) > 20:
        score += 5
    elif len(domain) > 15:
        score += 3

    # Number in domain (often used for uniqueness by scammers)
    if any(c.isdigit() for c in domain):
        score += 3

    return min(score, 100)


def run_investigation_safe(bounty: dict) -> dict | None:
    """Run investigation with full error handling."""
    try:
        from agent import run_investigation
        return run_investigation(bounty)
    except Exception as e:
        print(f"  [auto] Investigation failed for {bounty['domain']}: {e}")
        return None


def format_findings_summary(domain: str, results: dict) -> str:
    """Format a one-line summary of investigation findings."""
    if not results:
        return f"{domain}: FAILED"

    risk_level = results.get("risk_level", "unknown")
    risk_score = results.get("risk_score", 0)
    total_usd  = (results.get("blockchain") or {}).get("total_usd", 0)
    wallets    = sum(len(v) for v in
                     (results.get("social_osint") or {})
                     .get("wallets_from_html", {}).values())
    cluster    = len((results.get("passive_dns") or {})
                     .get("ip_pivot_domains", []))
    soa        = (results.get("whois") or {}).get("soa_email", "")

    parts = [f"{risk_level} ({risk_score}/100)"]
    if total_usd > 0:
        parts.append(f"${total_usd:,.0f} traced")
    if wallets > 0:
        parts.append(f"{wallets} wallets")
    if cluster > 0:
        parts.append(f"{cluster} IP cluster")
    if soa and "registrar" not in soa.lower():
        parts.append(f"SOA: {soa}")

    return f"{domain}: " + " | ".join(parts)


def is_high_value(results: dict) -> bool:
    """Determine if investigation results are worth flagging for submission."""
    if not results:
        return False
    risk_score = results.get("risk_score", 0)
    total_usd  = (results.get("blockchain") or {}).get("total_usd", 0)
    wallets    = sum(len(v) for v in
                     (results.get("social_osint") or {})
                     .get("wallets_from_html", {}).values())
    vt_hits    = (results.get("virustotal") or {}).get("malicious_votes", 0)

    return (
        risk_score >= 40 or
        total_usd > 1000 or
        wallets > 0 and total_usd > 0 or
        vt_hits >= 3
    )


def run_autonomous_cycle(max_domains: int = 10,
                         dry_run: bool = False) -> dict:
    """
    Run one full discovery + investigation cycle.
    Returns summary of findings.
    """
    from scripts.db import init_db, add_bounty
    from scripts.discover_scams import discover_scam_domains

    init_db()

    cycle_start = datetime.utcnow()
    print(f"\n{'='*60}")
    print(f"SCAMBUSTERS AUTONOMOUS CYCLE")
    print(f"Started: {cycle_start.isoformat()}")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"Max domains: {max_domains}")
    print(f"{'='*60}\n")

    # Step 1: Discover
    print("[1/3] Discovering scam domains...")
    all_discovered = discover_scam_domains(
        max_domains=max_domains * 5,  # Discover more than we'll investigate
        urlscan_api_key=os.getenv("URLSCAN_API_KEY", "")
    )

    # Step 2: Filter known domains
    print(f"\n[2/3] Filtering {len(all_discovered)} discovered domains...")
    known = get_known_domains()
    new_domains = [d for d in all_discovered if d not in known]
    print(f"  {len(new_domains)} new domains (filtered {len(all_discovered) - len(new_domains)} known)")

    # Step 3: Score and prioritize
    scored = sorted(new_domains, key=score_domain, reverse=True)
    targets = scored[:max_domains]

    print(f"\n  Top targets:")
    for i, d in enumerate(targets[:10]):
        print(f"    {i+1}. {d} (score: {score_domain(d)})")

    if dry_run:
        print("\n[DRY RUN] Skipping investigations.")
        return {"discovered": len(all_discovered), "new": len(new_domains),
                "would_investigate": targets}

    # Step 4: Investigate
    print(f"\n[3/3] Investigating {len(targets)} domains...")
    results_summary = []
    high_value_finds = []

    for i, domain in enumerate(targets):
        print(f"\n  [{i+1}/{len(targets)}] {domain}")

        # Create bounty record
        bounty_id = f"auto_{domain.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        bounty = {
            "bounty_id":  bounty_id,
            "domain":     domain,
            "target_url": f"https://{domain}",
            "sponsor":    "auto-discovery",
            "multiplier": 1.0,
            "raw":        f"Auto-discovered on {datetime.utcnow().date()}",
        }

        try:
            add_bounty(bounty)
        except Exception:
            pass  # Already exists

        # Investigate
        results = run_investigation_safe(bounty)
        summary = format_findings_summary(domain, results)
        results_summary.append(summary)
        print(f"  → {summary}")

        # Flag high value
        if results and is_high_value(results):
            high_value_finds.append({
                "domain":     domain,
                "bounty_id":  bounty_id,
                "risk_score": results.get("risk_score", 0),
                "risk_level": results.get("risk_level", "unknown"),
                "total_usd":  (results.get("blockchain") or {}).get("total_usd", 0),
                "summary":    summary,
            })
            print(f"  ⚠️  HIGH VALUE FIND — flagged for submission")

        # Rate limiting between investigations
        time.sleep(5)

    # Cycle complete
    cycle_end = datetime.utcnow()
    duration  = (cycle_end - cycle_start).seconds

    print(f"\n{'='*60}")
    print(f"CYCLE COMPLETE — {duration}s")
    print(f"Investigated: {len(targets)} domains")
    print(f"High-value finds: {len(high_value_finds)}")

    if high_value_finds:
        print(f"\n🎯 HIGH VALUE FINDINGS:")
        for find in high_value_finds:
            print(f"  {find['domain']} — {find['risk_level']} | ${find['total_usd']:,.0f} traced")

    print(f"{'='*60}\n")

    # Save cycle report
    report = {
        "cycle_start":      cycle_start.isoformat(),
        "cycle_end":        cycle_end.isoformat(),
        "duration_seconds": duration,
        "discovered":       len(all_discovered),
        "new_domains":      len(new_domains),
        "investigated":     len(targets),
        "high_value_finds": high_value_finds,
        "all_results":      results_summary,
    }

    os.makedirs("outputs", exist_ok=True)
    report_path = f"outputs/autonomous_cycle_{cycle_start.strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Cycle report saved to {report_path}")

    return report


def run_continuous(interval_hours: int = 4, max_per_cycle: int = 20):
    """
    Run autonomous cycles continuously on a schedule.
    Default: every 4 hours, 20 domains per cycle.
    """
    print(f"\n🤖 SCAMBUSTERS AUTONOMOUS MODE")
    print(f"   Cycle interval: {interval_hours} hours")
    print(f"   Domains per cycle: {max_per_cycle}")
    print(f"   Press Ctrl+C to stop\n")

    cycle_count = 0
    while True:
        cycle_count += 1
        print(f"\n{'='*60}")
        print(f"AUTONOMOUS CYCLE #{cycle_count}")
        print(f"{'='*60}")

        try:
            run_autonomous_cycle(max_domains=max_per_cycle)
        except KeyboardInterrupt:
            print("\n[auto] Stopped by user.")
            break
        except Exception as e:
            print(f"[auto] Cycle error: {e}")

        next_run = datetime.utcnow() + timedelta(hours=interval_hours)
        print(f"\n[auto] Next cycle at {next_run.strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"[auto] Sleeping for {interval_hours} hours...")

        try:
            time.sleep(interval_hours * 3600)
        except KeyboardInterrupt:
            print("\n[auto] Stopped by user.")
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScamBusters Autonomous Engine")
    parser.add_argument("--continuous", action="store_true",
                        help="Run continuously every N hours")
    parser.add_argument("--discover", action="store_true",
                        help="Discovery only, no investigation")
    parser.add_argument("--dry-run", action="store_true",
                        help="Discover and score but don't investigate")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of domains to investigate per cycle")
    parser.add_argument("--interval", type=int, default=4,
                        help="Hours between cycles (continuous mode)")
    args = parser.parse_args()

    if args.continuous:
        run_continuous(interval_hours=args.interval,
                       max_per_cycle=args.count)
    elif args.discover:
        from scripts.discover_scams import discover_scam_domains
        domains = discover_scam_domains(max_domains=100)
        print(f"\nFound {len(domains)} domains:")
        for d in domains[:30]:
            print(f"  {d} (score: {score_domain(d)})")
    else:
        run_autonomous_cycle(
            max_domains=args.count,
            dry_run=args.dry_run
        )
