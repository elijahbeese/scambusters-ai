"""
agent.py — ScamBusters Agent v1.0 Orchestrator
Runs the full investigation pipeline for a given domain/bounty.
Called by the Flask app for each queued bounty.
"""

import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from scripts.urlscan_lookup   import run_urlscan
from scripts.whois_lookup     import run_whois
from scripts.passive_dns      import run_passive_dns
from scripts.social_osint     import run_social_osint
from scripts.report_generator import generate_report
from scripts.takedown_drafter import draft_all_takedowns
from scripts.submission_packager import build_submission_package
from scripts.bounty_store     import save_investigation, update_status

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs/")


def run_investigation(bounty: dict, progress_callback=None) -> dict:
    """
    Run the full investigation pipeline for a bounty.
    progress_callback(stage, message) called at each step for live UI updates.
    """
    domain    = bounty["domain"]
    bounty_id = bounty["bounty_id"]
    results   = {}

    def progress(stage, msg):
        if progress_callback:
            progress_callback(stage, msg)
        else:
            print(f"  [{stage}] {msg}")

    update_status(bounty_id, "investigating")

    # Stage 2: URLScan
    progress("urlscan", f"Submitting {domain} to URLScan...")
    results["urlscan"] = run_urlscan(domain)
    results["similar_domains"] = results["urlscan"].pop("similar_domains", [])
    progress("urlscan", f"Done — IP: {results['urlscan'].get('primary_ip')}, "
             f"{len(results['similar_domains'])} similar sites")

    # Stage 3: WHOIS
    progress("whois", "Running WHOIS lookup...")
    results["whois"] = run_whois(domain)
    progress("whois", f"Registrar: {results['whois'].get('registrar')} | "
             f"SOA: {results['whois'].get('soa_email')}")

    # Stage 4: Passive DNS
    progress("passive_dns", "Querying Passive DNS...")
    soa_email = results["whois"].get("soa_email")
    results["passive_dns"] = run_passive_dns(domain, soa_email=soa_email)
    linked_count = len(results["passive_dns"].get("linked_domains", []))
    progress("passive_dns", f"Found {linked_count} linked domains")

    # Stage 5: Social OSINT
    progress("social_osint", "Extracting social links and wallets...")
    results["social_osint"] = run_social_osint(domain)
    wallet_count = sum(
        len(v) for v in results["social_osint"].get("wallets_from_html", {}).values()
    )
    progress("social_osint", f"Found {wallet_count} wallet addresses from HTML")

    # Stage 6: AI Report
    progress("report", "Generating AI intelligence report...")
    results["ai_report"] = generate_report(domain, results)
    progress("report", "Report generated")

    # Stage 7: Takedown drafts
    progress("takedowns", "Drafting takedown emails...")
    takedowns = draft_all_takedowns(domain, results)
    results["takedown_registrar"] = takedowns.get("registrar")
    results["takedown_hosting"]   = takedowns.get("hosting")
    progress("takedowns", "Takedown emails drafted — awaiting your approval")

    # Build submission package
    progress("packaging", "Building I4G submission package...")
    results["submission_package"] = build_submission_package(bounty, results)
    progress("packaging", "Package ready for review")

    # Save to DB
    save_investigation(bounty_id, domain, results)
    update_status(bounty_id, "complete")

    # Save JSON to disk
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_file = os.path.join(
        OUTPUT_DIR,
        f"{bounty_id}_{domain.replace('.', '_')}.json"
    )
    with open(out_file, "w") as f:
        json.dump({**bounty, **results}, f, indent=2, default=str)

    progress("done", f"Investigation complete — saved to {out_file}")
    return results


if __name__ == "__main__":
    import sys
    from scripts.bounty_store import init_db
    init_db()

    test_bounty = {
        "bounty_id": "test_001",
        "domain": sys.argv[1] if len(sys.argv) > 1 else "aitimart.com",
        "target_url": f"https://{sys.argv[1] if len(sys.argv) > 1 else 'aitimart.com'}",
        "sponsor": "Intelligence For Good",
        "multiplier": 1.0,
    }
    run_investigation(test_bounty)
