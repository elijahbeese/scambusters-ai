"""
agent.py — ScamBusters Agent v2.0 Orchestrator
9-stage investigation pipeline:
1. URLScan (infrastructure + similar sites)
2. WHOIS (registrar + SOA email)
3. Passive DNS (historical IPs + linked domains)
4. Social OSINT (social links + wallets from HTML)
5. Certificate OSINT (crt.sh subdomains + VirusTotal + Shodan)
6. Blockchain analysis (wallet transaction history + USD amounts)
7. AI Report (GPT-4o intelligence summary)
8. Risk Scoring (weighted 0-100 score)
9. Takedown + LE Package generation
"""

import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from scripts.urlscan_lookup      import run_urlscan
from scripts.whois_lookup        import run_whois
from scripts.passive_dns         import run_passive_dns
from scripts.social_osint        import run_social_osint
from scripts.cert_osint          import run_cert_osint
from scripts.blockchain          import analyze_all_wallets
from scripts.report_generator    import generate_report
from scripts.risk_scorer         import score_investigation
from scripts.takedown_drafter    import draft_all_takedowns
from scripts.le_packager         import build_le_package, generate_ic3_narrative
from scripts.submission_packager import build_submission_package
from scripts.network_graph       import build_graph_from_investigation
from scripts.db                  import (save_investigation, update_status,
                                          update_bounty_risk, upsert_wallet)

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs/")


def run_investigation(bounty: dict, progress_callback=None) -> dict:
    """
    Run the full 9-stage investigation pipeline.
    progress_callback(stage, message) for live UI updates via SSE.
    """
    domain    = bounty["domain"]
    bounty_id = bounty["bounty_id"]
    results   = {}

    def progress(stage, msg):
        if progress_callback:
            progress_callback(stage, msg)
        print(f"  [{stage}] {msg}")

    update_status(bounty_id, "investigating")

    # ── Stage 1: URLScan ──────────────────────────────────────────────────────
    progress("urlscan", f"Scanning {domain} on URLScan.io...")
    results["urlscan"] = run_urlscan(domain)
    results["similar_domains"] = results["urlscan"].pop("similar_domains", [])
    progress("urlscan",
             f"IP: {results['urlscan'].get('primary_ip')} | "
             f"{len(results['similar_domains'])} similar sites")

    # ── Stage 2: WHOIS ────────────────────────────────────────────────────────
    progress("whois", "Running WHOIS lookup...")
    results["whois"] = run_whois(domain)
    progress("whois",
             f"Registrar: {results['whois'].get('registrar')} | "
             f"SOA: {results['whois'].get('soa_email', 'not found')}")

    # ── Stage 3: Passive DNS ──────────────────────────────────────────────────
    progress("passive_dns", "Pivoting on Passive DNS...")
    soa_email = results["whois"].get("soa_email")
    results["passive_dns"] = run_passive_dns(domain, soa_email=soa_email)
    linked = len(results["passive_dns"].get("linked_domains", []))
    cluster = len(results["passive_dns"].get("soa_cluster_domains", []))
    progress("passive_dns", f"{linked} linked domains | {cluster} SOA cluster domains")

    # ── Stage 4: Social OSINT ─────────────────────────────────────────────────
    progress("social_osint", "Extracting social links and wallet addresses...")
    results["social_osint"] = run_social_osint(domain)
    wallets_found = sum(
        len(v) for v in
        results["social_osint"].get("wallets_from_html", {}).values()
    )
    progress("social_osint", f"{wallets_found} wallet addresses extracted from HTML")

    # ── Stage 5: Certificate OSINT ────────────────────────────────────────────
    progress("cert_osint", "Running crt.sh + VirusTotal + Shodan...")
    primary_ip = results["urlscan"].get("primary_ip")
    cert_data = run_cert_osint(domain, ip=primary_ip)
    results["cert_osint"] = cert_data.get("crtsh", {})
    results["virustotal"] = cert_data.get("virustotal", {})
    results["shodan"]     = cert_data.get("shodan", {})
    subdomains = len(results["cert_osint"].get("subdomains", []))
    vt_hits    = results["virustotal"].get("malicious_votes", 0)
    progress("cert_osint", f"{subdomains} subdomains | {vt_hits} VT malicious votes")

    # ── Stage 6: Blockchain Analysis ─────────────────────────────────────────
    progress("blockchain", "Analyzing crypto wallet transaction history...")
    all_wallets = results["social_osint"].get("wallets_from_html", {})
    if all_wallets:
        blockchain_data = analyze_all_wallets(all_wallets)
        results["blockchain"] = blockchain_data
        total_usd = blockchain_data.get("total_usd", 0)
        progress("blockchain", f"${total_usd:,.2f} traced on-chain across {blockchain_data.get('wallet_count', 0)} wallets")

        # Persist wallets to DB
        for currency, wallet_list in blockchain_data.get("by_currency", {}).items():
            for w in wallet_list:
                if isinstance(w, dict) and w.get("address"):
                    upsert_wallet(domain, bounty_id, currency, w["address"], w)
    else:
        results["blockchain"] = {"total_usd": 0, "wallet_count": 0, "by_currency": {}}
        progress("blockchain", "No wallet addresses found to analyze")

    # ── Stage 7: AI Report ────────────────────────────────────────────────────
    progress("report", "Generating AI intelligence report (GPT-4o)...")
    results["ai_report"] = generate_report(domain, results)
    progress("report", "Intelligence report generated")

    # ── Stage 8: Risk Scoring ─────────────────────────────────────────────────
    progress("risk", "Calculating risk score...")
    risk = score_investigation(results)
    results["risk_score"]     = risk["score"]
    results["risk_level"]     = risk["level"]
    results["risk_breakdown"] = risk["breakdown"]
    update_bounty_risk(bounty_id, risk["score"], risk["level"])
    progress("risk", f"{risk['level']} ({risk['score']}/100) — {risk['summary']}")

    # ── Stage 9: Takedowns + LE Package ──────────────────────────────────────
    progress("takedowns", "Drafting takedown emails...")
    takedowns = draft_all_takedowns(domain, results)
    results["takedown_registrar"] = takedowns.get("registrar")
    results["takedown_hosting"]   = takedowns.get("hosting")

    progress("packaging", "Building I4G submission + LE referral packages...")
    results["submission_package"] = build_submission_package(bounty, results)
    le_pkg = build_le_package(bounty, results)
    le_pkg["ic3_narrative"] = generate_ic3_narrative(le_pkg)
    results["le_package"] = le_pkg

    # Build network graph edges
    progress("graph", "Building network graph...")
    try:
        build_graph_from_investigation(domain, results)
        progress("graph", "Network edges stored")
    except Exception as e:
        progress("graph", f"Graph build failed (non-critical): {e}")

    # Persist everything
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

    progress("done", f"Complete — {risk['level']} risk | ${results['blockchain'].get('total_usd', 0):,.0f} traced | saved to {out_file}")
    return results


if __name__ == "__main__":
    import sys
    from scripts.db import init_db
    init_db()

    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    test_bounty = {
        "bounty_id":  f"test_{domain.replace('.','_')}",
        "domain":     domain,
        "target_url": f"https://{domain}",
        "sponsor":    "test",
        "multiplier": 1.0,
    }
    run_investigation(test_bounty)
