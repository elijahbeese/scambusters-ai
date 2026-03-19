"""
agent.py — ScamBusters Agent v2.0 Orchestrator
9-stage investigation pipeline with improved data flow between stages.
Key fixes:
- Primary IP passed to passive DNS for IP pivot
- SOA email passed to passive DNS for operator clustering
- All stages get data from previous stages
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
from scripts.db                  import (add_bounty, save_investigation,
                                          update_status, update_bounty_risk,
                                          upsert_wallet, init_db)

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs/")


def run_investigation(bounty: dict, progress_callback=None) -> dict:
    domain    = bounty["domain"]
    bounty_id = bounty["bounty_id"]
    results   = {}

    def progress(stage, msg):
        if progress_callback:
            progress_callback(stage, msg)
        print(f"  [{stage}] {msg}")

    update_status(bounty_id, "investigating")

    # Stage 1: URLScan
    progress("urlscan", f"Scanning {domain} on URLScan.io...")
    urlscan_data = run_urlscan(domain)
    similar_domains = urlscan_data.pop("similar_domains", [])
    results["urlscan"] = urlscan_data
    results["similar_domains"] = similar_domains
    primary_ip = urlscan_data.get("primary_ip")
    asn_name   = urlscan_data.get("asn_name")
    progress("urlscan",
             f"IP: {primary_ip or 'not found'} | ASN: {asn_name or 'unknown'} | "
             f"{len(similar_domains)} similar sites")

    # Stage 2: WHOIS
    progress("whois", "Running WHOIS + RDAP lookup...")
    results["whois"] = run_whois(domain)
    soa_email   = results["whois"].get("soa_email")
    registrar   = results["whois"].get("registrar")
    abuse_email = results["whois"].get("registrar_abuse_email")
    progress("whois",
             f"Registrar: {registrar or 'unknown'} | "
             f"Abuse: {abuse_email or 'not found'} | "
             f"SOA: {soa_email or 'not found'}")

    # Stage 3: Passive DNS (now gets IP + SOA from previous stages)
    progress("passive_dns", f"Pivoting on Passive DNS...")
    results["passive_dns"] = run_passive_dns(
        domain,
        soa_email=soa_email,
        primary_ip=primary_ip
    )
    linked  = len(results["passive_dns"].get("linked_domains", []))
    cluster = len(results["passive_dns"].get("soa_cluster_domains", []))
    pivots  = len(results["passive_dns"].get("ip_pivot_domains", []))
    progress("passive_dns",
             f"{linked} linked | {cluster} SOA cluster | {pivots} IP pivot domains")

    # Stage 3.5: Auto-investigate top IP cluster domains
    ip_pivot_domains = results["passive_dns"].get("ip_pivot_domains", [])
    if ip_pivot_domains and len(ip_pivot_domains) > 0:
        # Score and pick top 3 most scam-like domains from the cluster
        scam_keywords = ["invest", "stake", "capital", "trade", "crypto", "earn",
                         "fund", "profit", "wealth", "coin", "bitcoin", "finance",
                         "yield", "mining", "asset", "signal", "broker"]
        def cluster_score(d):
            return sum(2 for kw in scam_keywords if kw in d.lower())
        
        top_cluster = sorted(ip_pivot_domains, key=cluster_score, reverse=True)[:3]
        cluster_wallets_found = {}
        
        for cluster_domain in top_cluster:
            try:
                from scripts.wallet_harvester import harvest_wallets_sync
                cluster_result = harvest_wallets_sync(cluster_domain, OUTPUT_DIR)
                cluster_wallets = cluster_result.get("wallets", {})
                if cluster_wallets:
                    cluster_usd = cluster_result.get("total_usd", 0)
                    progress("cluster", 
                             f"{cluster_domain}: {sum(len(v) for v in cluster_wallets.values())} wallets | ${cluster_usd:,.2f}")
                    for currency, addrs in cluster_wallets.items():
                        if currency not in cluster_wallets_found:
                            cluster_wallets_found[currency] = []
                        cluster_wallets_found[currency].extend(
                            a for a in addrs if a not in cluster_wallets_found.get(currency, [])
                        )
            except Exception:
                continue
        
        if cluster_wallets_found:
            results["cluster_wallets"] = cluster_wallets_found
            existing = results.get("social_osint", {}).get("wallets_from_html", {})
            for currency, addrs in cluster_wallets_found.items():
                if currency not in existing:
                    existing[currency] = []
                for addr in addrs:
                    if addr not in existing[currency]:
                        existing[currency].append(addr)

    # Stage 4: Social OSINT
    progress("social_osint", "Deep-scraping site for social links, wallets, phones...")
    results["social_osint"] = run_social_osint(domain)
    wallets_found = sum(
        len(v) for v in results["social_osint"].get("wallets_from_html", {}).values()
    )
    phones_found  = len(results["social_osint"].get("contact_info", {}).get("phones", []))
    emails_found  = len(results["social_osint"].get("contact_info", {}).get("emails", []))
    pages_scraped = results["social_osint"].get("pages_scraped", 1)
    progress("social_osint",
             f"{wallets_found} wallets | {phones_found} phones | "
             f"{emails_found} emails | {pages_scraped} pages scraped")

    # Stage 4.5: Headless wallet harvesting
    progress("harvester", "Launching headless browser to extract deposit wallets...")
    try:
        from scripts.wallet_harvester import harvest_wallets_sync
        harvest_result = harvest_wallets_sync(domain, OUTPUT_DIR)
        harvested_wallets = harvest_result.get("wallets", {})

        # Merge harvested wallets into social_osint wallets
        existing_wallets = results["social_osint"].get("wallets_from_html", {})
        for currency, addresses in harvested_wallets.items():
            if currency not in existing_wallets:
                existing_wallets[currency] = []
            for addr in addresses:
                if addr not in existing_wallets[currency]:
                    existing_wallets[currency].append(addr)
        results["social_osint"]["wallets_from_html"] = existing_wallets
        results["wallet_harvest"] = harvest_result

        total_harvested = harvest_result.get("wallet_count", 0)
        total_usd_harvested = harvest_result.get("total_usd", 0)
        progress("harvester",
                 f"{total_harvested} wallets | ${total_usd_harvested:,.2f} traced | "
                 f"registration: {'yes' if harvest_result.get('registration_attempted') else 'no'} | "
                 f"{len(harvest_result.get('screenshots', []))} screenshots")
    except Exception as e:
        progress("harvester", f"Harvester skipped: {e}")

    # Stage 5: Certificate OSINT
    progress("cert_osint", "Running crt.sh + VirusTotal + Shodan...")
    cert_data = run_cert_osint(domain, ip=primary_ip)
    results["cert_osint"] = cert_data.get("crtsh", {})
    results["virustotal"] = cert_data.get("virustotal", {})
    results["shodan"]     = cert_data.get("shodan", {})
    subdomains = len((results["cert_osint"] or {}).get("subdomains", []))
    vt_hits    = (results["virustotal"] or {}).get("malicious_votes", 0)
    vt_susp    = (results["virustotal"] or {}).get("suspicious_votes", 0)
    ports      = len((results["shodan"] or {}).get("open_ports", []))
    progress("cert_osint",
             f"{subdomains} subdomains | VT: {vt_hits} malicious, "
             f"{vt_susp} suspicious | {ports} open ports")

    # Stage 6: Blockchain
    progress("blockchain", "Analyzing crypto wallet transaction history...")
    all_wallets = results["social_osint"].get("wallets_from_html", {})
    harvest_usd = (results.get("wallet_harvest") or {}).get("total_usd", 0)

    if all_wallets:
        blockchain_data = analyze_all_wallets(all_wallets)
        total_usd    = blockchain_data.get("total_usd", 0)
        wallet_count = blockchain_data.get("wallet_count", 0)
        # Use whichever traced more — harvester or blockchain stage
        if harvest_usd > total_usd:
            blockchain_data["total_usd"] = harvest_usd
            total_usd = harvest_usd
        results["blockchain"] = blockchain_data
        progress("blockchain", f"${total_usd:,.2f} traced | {wallet_count} wallets")
        for currency, wallet_list in blockchain_data.get("by_currency", {}).items():
            for w in wallet_list:
                if isinstance(w, dict) and w.get("address"):
                    upsert_wallet(domain, bounty_id, currency, w["address"], w)
    else:
        results["blockchain"] = {
            "total_usd": 0, "wallet_count": 0, "by_currency": {},
            "note": "No wallets found. Manual deposit page extraction required."
        }
        progress("blockchain", "No wallets found")

    # Stage 7: AI Report
    progress("report", "Generating AI intelligence report (GPT-4o)...")
    results["ai_report"] = generate_report(domain, results)
    progress("report", "Intelligence report generated")

    # Stage 8: Risk Scoring
    progress("risk", "Calculating risk score...")
    risk = score_investigation(results)
    results["risk_score"]     = risk["score"]
    results["risk_level"]     = risk["level"]
    results["risk_breakdown"] = risk["breakdown"]
    update_bounty_risk(bounty_id, risk["score"], risk["level"])
    progress("risk", f"{risk['level']} ({risk['score']}/100) — {risk['summary']}")

    # Stage 9: Takedowns + LE Package
    progress("takedowns", "Drafting takedown emails...")
    takedowns = draft_all_takedowns(domain, results)
    results["takedown_registrar"] = takedowns.get("registrar")
    results["takedown_hosting"]   = takedowns.get("hosting")

    progress("packaging", "Building I4G submission + LE referral packages...")
    results["submission_package"] = build_submission_package(bounty, results)
    le_pkg = build_le_package(bounty, results)
    le_pkg["ic3_narrative"] = generate_ic3_narrative(le_pkg)
    results["le_package"] = le_pkg

    # Network graph
    progress("graph", "Building network graph...")
    try:
        build_graph_from_investigation(domain, results)
        progress("graph", "Network edges stored")
    except Exception as e:
        progress("graph", f"Graph build failed (non-critical): {e}")

    # Save to DB and disk
    save_investigation(bounty_id, domain, results)
    update_status(bounty_id, "complete")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_file = os.path.join(OUTPUT_DIR,
        f"{bounty_id}_{domain.replace('.', '_')}.json")
    with open(out_file, "w") as f:
        json.dump({**bounty, **results}, f, indent=2, default=str)

    total_usd = results["blockchain"].get("total_usd", 0)
    progress("done",
             f"Complete — {risk['level']} ({risk['score']}/100) | "
             f"${total_usd:,.0f} traced | {cluster} operator-linked domains | "
             f"saved to {out_file}")

    return results


if __name__ == "__main__":
    import sys
    init_db()

    domain = sys.argv[1] if len(sys.argv) > 1 else "stake2earn.app"
    test_bounty = {
        "bounty_id":  f"test_{domain.replace('.', '_')}",
        "domain":     domain,
        "target_url": f"https://{domain}",
        "sponsor":    "test",
        "multiplier": 1.0,
        "raw":        f"CLI test run for {domain}",
    }
    add_bounty(test_bounty)
    run_investigation(test_bounty)
