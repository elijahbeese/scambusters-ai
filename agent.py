"""
ScamBusters Agent — Main Orchestrator
Runs the full investigation pipeline end to end.
"""

import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from scripts.discover_scams import discover_scam_domains
from scripts.urlscan_lookup import run_urlscan
from scripts.whois_lookup import run_whois
from scripts.passive_dns import run_passive_dns
from scripts.social_osint import run_social_osint
from scripts.report_generator import generate_report

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs/")
MAX_DOMAINS = int(os.getenv("MAX_DOMAINS_PER_RUN", 20))


def run_pipeline():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(OUTPUT_DIR, f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    print("\n" + "="*60)
    print("  SCAMBUSTERS AGENT — Starting investigation pipeline")
    print("="*60 + "\n")

    # Stage 1: Discovery
    print("[1/6] Discovering scam domains from HYIP monitors...")
    domains = discover_scam_domains(max_domains=MAX_DOMAINS)
    print(f"      Found {len(domains)} domains.\n")

    results = []

    for i, domain in enumerate(domains, 1):
        print(f"[Domain {i}/{len(domains)}] Investigating: {domain}")
        scam_data = {"domain": domain, "timestamp": timestamp}

        # Stage 2: URLScan
        print("  → URLScan...")
        scam_data["urlscan"] = run_urlscan(domain)

        # Stage 3: WHOIS
        print("  → WHOIS...")
        scam_data["whois"] = run_whois(domain)

        # Stage 4: Passive DNS
        print("  → Passive DNS...")
        scam_data["passive_dns"] = run_passive_dns(domain)

        # Stage 5: Social OSINT
        print("  → Social OSINT + Google Dorking...")
        scam_data["social_osint"] = run_social_osint(domain)

        # Stage 6: Report Generation
        print("  → Generating AI report...")
        scam_data["report"] = generate_report(scam_data)

        results.append(scam_data)

        # Save per-domain JSON
        domain_file = os.path.join(run_dir, f"{domain.replace('.', '_')}.json")
        with open(domain_file, "w") as f:
            json.dump(scam_data, f, indent=2, default=str)

        print(f"  ✓ Saved to {domain_file}\n")

    # Save full run summary
    summary_file = os.path.join(run_dir, "summary.json")
    with open(summary_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print("="*60)
    print(f"  Pipeline complete. {len(results)} domains investigated.")
    print(f"  Results saved to: {run_dir}")
    print(f"  Launch dashboard: python app.py")
    print("="*60 + "\n")

    return run_dir


if __name__ == "__main__":
    run_pipeline()
