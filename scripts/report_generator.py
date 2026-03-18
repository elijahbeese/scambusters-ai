"""
Stage 6: report_generator.py
GPT-4o compiles all collected OSINT into a structured intelligence report
formatted for I4G submission.

Per I4G docs, the deliverable should include:
- Domain + all linked/similar domains
- All crypto wallet addresses
- Registrar + abuse contact
- Hosting provider + ASN
- Social media channels
- SOA email (for threat actor clustering)
- Takedown targets
"""

import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are a senior cybersecurity analyst at Intelligence For Good (I4G),
specializing in crypto investment scam (HYIP) investigations.

You receive raw OSINT data collected about a fraudulent cryptocurrency investment site
and produce a structured intelligence report for:
1. Registrar/hosting provider takedown requests
2. Law enforcement referral
3. I4G database submission (sam@intelligenceForGood.org)

Your report MUST include these sections:

## THREAT SUMMARY
2-3 sentences. What is this site, who operates it, what is the victim impact.

## INFRASTRUCTURE
- Primary IP:
- ASN / Hosting Provider:
- Hosting Country:
- Registrar:
- Registration Date:
- Registrar Abuse Contact:
- SOA Email: (CRITICAL — used for threat actor clustering)

## LINKED DOMAINS
List all related domains discovered via pDNS and URLScan similarity.
Note if they share IPs, registrars, or SOA emails — this indicates same operator.

## CRYPTOCURRENCY WALLETS
List every wallet address by currency. These are the money collection points.
Format: CURRENCY: address

## SOCIAL MEDIA FOOTPRINT
Telegram channels, WhatsApp groups, Facebook groups used to recruit victims.

## TAKEDOWN TARGETS
1. Registrar: [name] — [abuse email]
2. Hosting: [ASN org] — [abuse contact or website]

## RISK ASSESSMENT
Rate: LOW / MEDIUM / HIGH / CRITICAL
Justify based on: wallet activity indicators, number of linked domains, social reach.

## RECOMMENDED ACTIONS
Prioritized list of next steps.

Be direct, factual, and terse. No hedging. This is an internal analyst report."""


def generate_report(domain: str, investigation_data: dict) -> dict:
    osint = {
        "domain": domain,
        "urlscan": investigation_data.get("urlscan", {}),
        "whois": investigation_data.get("whois", {}),
        "passive_dns": investigation_data.get("passive_dns", {}),
        "social_osint": investigation_data.get("social_osint", {}),
        "similar_domains": investigation_data.get("similar_domains", []),
    }

    prompt = f"""Analyze the following OSINT data for crypto investment scam: {domain}

{json.dumps(osint, indent=2, default=str)}

Generate the complete intelligence report."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        return {
            "status": "success",
            "domain": domain,
            "report": response.choices[0].message.content,
            "model": "gpt-4o",
        }
    except Exception as e:
        return {"status": "error", "domain": domain, "error": str(e)}


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    mock = {
        "urlscan": {"primary_ip": "79.143.87.241", "asn_name": "Hydra Communications", "country": "GB"},
        "whois": {"registrar": "WebNic.cc", "creation_date": "2023-08-27",
                  "registrar_abuse_email": "abuse@webnic.cc", "soa_email": "admin@scamhost.com"},
        "passive_dns": {"historical_ips": ["79.143.87.241"], "linked_domains": ["aitiusers.com"]},
        "social_osint": {"social_links": {"telegram": ["https://t.me/aitimart_official"]}},
    }
    result = generate_report(domain, mock)
    print(result.get("report", result.get("error")))
