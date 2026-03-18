"""
le_packager.py — Law Enforcement Referral Package Generator
Produces an IC3-formatted intelligence bundle suitable for submission to:
- FBI Internet Crime Complaint Center (IC3)
- Secret Service Electronic Crimes Task Forces
- FTC Consumer Sentinel Network
- Intelligence For Good (sam@intelligenceForGood.org)

Per I4G docs: The goal is clean, structured, evidence-packed packages.
Federal analysts get garbage submissions constantly. A properly formatted
package with blockchain evidence, infrastructure mapping, and victim
loss estimates gets acted on. Garbage gets filed.
"""

import os
import json
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def build_le_package(bounty: dict, investigation: dict) -> dict:
    """
    Build the complete law enforcement package from all investigation data.
    """
    domain    = bounty.get("domain", "unknown")
    whois     = investigation.get("whois", {}) or {}
    urlscan   = investigation.get("urlscan", {}) or {}
    pdns      = investigation.get("passive_dns", {}) or {}
    social    = investigation.get("social_osint", {}) or {}
    blockchain = investigation.get("blockchain", {}) or {}
    similar   = investigation.get("similar_domains", []) or []
    vt        = investigation.get("virustotal", {}) or {}
    crt       = investigation.get("cert_osint", {}) or {}
    risk      = investigation.get("risk_breakdown", {}) or {}
    ai_report = investigation.get("ai_report", {}) or {}

    # Aggregate all wallet addresses with blockchain data
    wallet_evidence = []
    bc_by_currency = blockchain.get("by_currency", {}) or {}
    for currency, wallets in bc_by_currency.items():
        for w in wallets:
            if isinstance(w, dict) and not w.get("error"):
                wallet_evidence.append({
                    "currency":           currency,
                    "address":            w.get("address"),
                    "tx_count":           w.get("tx_count", 0),
                    "total_received_usd": w.get("total_received_usd", 0),
                    "first_seen":         w.get("first_seen"),
                    "last_seen":          w.get("last_seen"),
                    "is_active":          w.get("is_active", False),
                    "explorer_url":       w.get("explorer_url"),
                })

    total_usd = blockchain.get("total_usd", 0)

    # All linked domains
    all_linked = list(set(
        [s.get("domain") for s in similar if s.get("domain")] +
        (pdns.get("linked_domains") or []) +
        (pdns.get("ip_pivot_domains") or []) +
        (pdns.get("soa_cluster_domains") or [])
    ) - {domain})

    # Social channels
    social_channels = []
    for platform, links in (social.get("social_links") or {}).items():
        for link in (links or []):
            social_channels.append({"platform": platform, "url": link})

    package = {
        "package_metadata": {
            "generated_at":     datetime.utcnow().isoformat(),
            "generated_by":     "ScamBusters Agent v2.0",
            "tool_github":      "https://github.com/elijahbeese/scambusters-agent",
            "i4g_bounty_id":    bounty.get("bounty_id"),
            "investigator":     "[YOUR NAME]",
            "organization":     "Intelligence For Good / University of Tampa",
        },
        "subject": {
            "primary_domain":   domain,
            "target_url":       bounty.get("target_url") or f"https://{domain}",
            "classification":   "High Yield Investment Program (HYIP) / Crypto Investment Scam",
            "risk_level":       investigation.get("risk_level", "unknown"),
            "risk_score":       investigation.get("risk_score", 0),
        },
        "infrastructure": {
            "primary_ip":       urlscan.get("primary_ip"),
            "asn":              urlscan.get("asn_name"),
            "hosting_country":  urlscan.get("country"),
            "hosting_provider": urlscan.get("asn_name"),
            "server":           urlscan.get("server"),
            "urlscan_report":   urlscan.get("report_url"),
            "screenshot":       urlscan.get("screenshot_url"),
            "open_ports":       (investigation.get("shodan") or {}).get("open_ports", []),
            "subdomains":       (crt.get("crtsh") or {}).get("subdomains", []),
        },
        "registration": {
            "registrar":        whois.get("registrar"),
            "creation_date":    whois.get("creation_date"),
            "expiration_date":  whois.get("expiration_date"),
            "abuse_email":      whois.get("registrar_abuse_email"),
            "abuse_phone":      whois.get("registrar_abuse_phone"),
            "soa_email":        whois.get("soa_email"),
            "name_servers":     whois.get("name_servers", []),
            "registrant_org":   whois.get("org"),
        },
        "financial_evidence": {
            "total_victim_losses_usd": total_usd,
            "wallet_count":     len(wallet_evidence),
            "wallets":          wallet_evidence,
            "active_wallets":   [w for w in wallet_evidence if w.get("is_active")],
            "note": (
                f"${total_usd:,.2f} in victim losses traced on blockchain. "
                f"{len([w for w in wallet_evidence if w.get('is_active')])} wallets still active."
            ) if total_usd > 0 else "Blockchain analysis pending or no wallets identified.",
        },
        "network_intel": {
            "linked_domain_count": len(all_linked),
            "linked_domains":      all_linked[:50],
            "clone_count":         len(similar),
            "soa_cluster_size":    len(pdns.get("soa_cluster_domains") or []),
            "threat_actor_note": (
                f"SOA email {whois.get('soa_email')} linked to "
                f"{len(pdns.get('soa_cluster_domains') or [])} domains. "
                "Indicates single operator managing multiple scam sites."
            ) if whois.get("soa_email") else "SOA email not identified.",
        },
        "social_media": {
            "channels":      social_channels,
            "channel_count": len(social_channels),
            "contact_emails": (social.get("contact_info") or {}).get("emails", []),
        },
        "threat_intelligence": {
            "virustotal_malicious": (vt.get("virustotal") or vt).get("malicious_votes", 0),
            "virustotal_url":       (vt.get("virustotal") or vt).get("vt_url"),
            "flagging_engines":     (vt.get("virustotal") or vt).get("flagging_engines", []),
        },
        "analyst_report":     (ai_report.get("report") if isinstance(ai_report, dict)
                               else str(ai_report)),
        "recommended_actions": [
            f"Submit takedown to registrar: {whois.get('registrar')} ({whois.get('registrar_abuse_email')})",
            f"Submit takedown to hosting provider: {urlscan.get('asn_name')}",
            "File IC3 complaint at ic3.gov",
            f"Monitor {len(all_linked)} linked domains for reactivation",
            "Flag wallet addresses with crypto exchanges for AML review",
        ] if total_usd > 0 else [
            f"Submit takedown to registrar: {whois.get('registrar')}",
            "Monitor for site reactivation",
        ],
    }

    return package


def generate_ic3_narrative(package: dict) -> str:
    """
    Generate an IC3-formatted narrative using GPT-4o.
    IC3 wants: who, what, when, how much, evidence.
    """
    domain    = package["subject"]["primary_domain"]
    total_usd = package["financial_evidence"]["total_victim_losses_usd"]
    wallet_count = package["financial_evidence"]["wallet_count"]
    linked = package["network_intel"]["linked_domain_count"]

    prompt = f"""You are preparing an IC3 (FBI Internet Crime Complaint Center) 
complaint narrative for a crypto investment scam.

Complaint type: Investment Fraud / Cryptocurrency Fraud

Facts:
- Primary scam domain: {domain}
- Classification: High Yield Investment Program (HYIP) / Crypto Investment Scam
- Total victim losses traced on blockchain: ${total_usd:,.2f}
- Wallet addresses identified: {wallet_count}
- Linked/clone domains: {linked}
- Registrar: {package['registration']['registrar']}
- Registration date: {package['registration']['creation_date']}
- Hosting: {package['infrastructure']['asn']} ({package['infrastructure']['hosting_country']})
- SOA email: {package['registration']['soa_email']}

Write a formal, factual IC3 complaint narrative (3-4 paragraphs) that:
1. Describes what the site does and how victims are defrauded
2. Presents the technical evidence (infrastructure, registration, blockchain)
3. Describes the network scope (linked domains, operator)
4. States the requested law enforcement action

Be direct and factual. Use IC3 terminology. No hedging."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[IC3 narrative generation failed: {e}]"


def format_le_email(package: dict, target: str = "i4g") -> str:
    """Format the LE package as an email body."""
    domain    = package["subject"]["primary_domain"]
    total_usd = package["financial_evidence"]["total_victim_losses_usd"]
    wallet_count = package["financial_evidence"]["wallet_count"]
    meta = package["package_metadata"]
    reg = package["registration"]
    infra = package["infrastructure"]
    net = package["network_intel"]

    wallets_str = "\n".join(
        f"  {w['currency']}: {w['address']} "
        f"(${w['total_received_usd']:,.2f} received, {w['tx_count']} txs)"
        for w in package["financial_evidence"]["wallets"][:10]
    ) or "  None identified"

    linked_str = "\n".join(
        f"  - {d}" for d in (net.get("linked_domains") or [])[:15]
    ) or "  None identified"

    if target == "i4g":
        subject = f"ScamBusters v2 Submission — {domain} [{meta['i4g_bounty_id']}]"
        recipient = "sam@intelligenceForGood.org"
    else:
        subject = f"IC3 Complaint — Crypto Investment Fraud: {domain}"
        recipient = "ic3.gov complaint portal"

    return f"""To: {recipient}
Subject: {subject}

{'='*60}
SCAM INTELLIGENCE REPORT
Generated: {meta['generated_at']}
Tool: {meta['generated_by']}
Bounty ID: {meta['i4g_bounty_id']}
Risk Level: {package['subject']['risk_level']} ({package['subject']['risk_score']}/100)
{'='*60}

TARGET: {domain}
URL: {package['subject']['target_url']}
Classification: {package['subject']['classification']}

INFRASTRUCTURE:
  Primary IP: {infra.get('primary_ip', '—')}
  Hosting: {infra.get('asn', '—')} ({infra.get('hosting_country', '—')})
  URLScan: {infra.get('urlscan_report', '—')}

REGISTRATION:
  Registrar: {reg.get('registrar', '—')}
  Registered: {reg.get('creation_date', '—')}
  Abuse Email: {reg.get('abuse_email', '—')}
  SOA Email: {reg.get('soa_email', '—')}  ← key for operator clustering

FINANCIAL EVIDENCE:
  Total Victim Losses (blockchain traced): ${total_usd:,.2f}
  Wallet Addresses: {wallet_count}
{wallets_str}

NETWORK SCOPE:
  Linked/Clone Domains: {net.get('linked_domain_count', 0)}
{linked_str}

ANALYST REPORT:
{package.get('analyst_report', 'See attached JSON')[:2000]}

{'='*60}
RECOMMENDED ACTIONS:
{chr(10).join(f'  {i+1}. {a}' for i, a in enumerate(package.get('recommended_actions', [])))}

Generated by ScamBusters Agent v2.0
{meta['tool_github']}
"""


if __name__ == "__main__":
    import sys, json
    print("LE packager loaded. Call build_le_package() with bounty + investigation data.")
