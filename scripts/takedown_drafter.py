"""
Stage 7: takedown_drafter.py
Generates formal takedown emails to registrar and hosting provider.
Per I4G docs: include legal letterhead language, domain evidence,
specific ToS violations, and request suspension.
Only fires after human approval.
"""

import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are drafting a formal abuse/takedown notice on behalf of
Intelligence For Good (IntelligenceForGood.org), a cybersecurity nonprofit that
investigates crypto investment scams.

Your email must:
- Be professional, direct, and factual
- Cite specific evidence (domain, IP, registration date, scam description)
- Reference the provider's Terms of Service violation
- Make a specific, actionable request (suspend domain / terminate hosting)
- Include contact info placeholder for follow-up

Structure:
Subject: [clear subject line]
---
[Body: introduction, evidence, ToS reference, specific request, contact]

Tone: Professional. No threats. No emotion. This email exists to get the domain killed."""


def draft_takedown_email(domain: str, investigation: dict, target: str = "registrar") -> dict:
    whois   = investigation.get("whois", {})
    urlscan = investigation.get("urlscan", {})
    report  = investigation.get("ai_report", {})
    report_text = report.get("report", "") if isinstance(report, dict) else str(report)

    if target == "registrar":
        recipient  = whois.get("registrar_abuse_email", "[REGISTRAR ABUSE EMAIL]")
        provider   = whois.get("registrar", "[REGISTRAR]")
        provider_type = "domain registrar"
    else:
        recipient  = "[HOSTING ABUSE EMAIL — find at provider website]"
        provider   = urlscan.get("asn_name", "[HOSTING PROVIDER]")
        provider_type = "web hosting provider"

    prompt = f"""Draft a formal takedown notice to the {provider_type} for this crypto investment scam:

Domain: {domain}
Provider: {provider}
Recipient: {recipient}
Primary IP: {urlscan.get('primary_ip', 'Unknown')}
ASN: {urlscan.get('asn_name', 'Unknown')} ({urlscan.get('country', '?')})
Registration Date: {whois.get('creation_date', 'Unknown')}
Registrar: {whois.get('registrar', 'Unknown')}
SOA Email: {whois.get('soa_email', 'Unknown')}

Intelligence summary (first 800 chars):
{report_text[:800]}

Draft the complete email including subject line."""

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
            "target": target,
            "recipient": recipient,
            "provider": provider,
            "email_draft": response.choices[0].message.content,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def draft_all_takedowns(domain: str, investigation: dict) -> dict:
    return {
        "registrar": draft_takedown_email(domain, investigation, "registrar"),
        "hosting":   draft_takedown_email(domain, investigation, "hosting"),
    }
