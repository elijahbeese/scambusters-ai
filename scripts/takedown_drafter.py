"""
Stage 7: takedown_drafter.py
Generates formal abuse/takedown emails to registrars and hosting providers.
Only called after human approval in the review dashboard.
"""

import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

TAKEDOWN_SYSTEM_PROMPT = """You are a cybersecurity professional drafting formal abuse reports to domain registrars
and web hosting providers. Your emails are professional, factual, and cite specific evidence.
They are written to compel action, not to vent frustration.

Structure:
- Subject line
- Brief introduction (who you are, what you found)
- Specific evidence of fraud (domain details, registration info, scam description)
- Direct violation of the provider's Terms of Service
- Clear request (domain suspension / hosting termination)
- Contact information placeholder

Tone: Professional, direct, concise. No threats. No emotion."""


def draft_takedown_email(scam_data: dict, target: str = "registrar") -> dict:
    """
    Draft a formal takedown email.
    target: 'registrar' or 'hosting'
    """
    domain = scam_data.get("domain", "unknown")
    whois = scam_data.get("whois", {})
    urlscan = scam_data.get("urlscan", {})
    report = scam_data.get("report", {}).get("report", "No report available.")

    if target == "registrar":
        recipient = whois.get("registrar_abuse_email", "[REGISTRAR ABUSE EMAIL]")
        provider = whois.get("registrar", "[REGISTRAR NAME]")
        provider_type = "domain registrar"
    else:
        recipient = "[HOSTING PROVIDER ABUSE EMAIL — find via provider website]"
        provider = urlscan.get("asn_name", "[HOSTING PROVIDER]")
        provider_type = "web hosting provider"

    prompt = f"""Draft a formal takedown request to the {provider_type} for the following crypto investment scam:

Domain: {domain}
Provider: {provider}
Recipient email: {recipient}

Registration details:
- Registrar: {whois.get('registrar')}
- Creation date: {whois.get('creation_date')}
- IP address: {urlscan.get('primary_ip')}
- Hosting: {urlscan.get('asn_name')} ({urlscan.get('country')})

Intelligence summary:
{report[:1000]}

Draft the complete email including subject line."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": TAKEDOWN_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )

        email_text = response.choices[0].message.content

        return {
            "status": "success",
            "target": target,
            "recipient": recipient,
            "provider": provider,
            "email_draft": email_text,
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}


def draft_all_takedowns(scam_data: dict) -> dict:
    """Draft both registrar and hosting takedown emails."""
    return {
        "registrar": draft_takedown_email(scam_data, "registrar"),
        "hosting": draft_takedown_email(scam_data, "hosting"),
    }


if __name__ == "__main__":
    import json, sys
    # Load a saved scam JSON for testing
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            data = json.load(f)
        result = draft_all_takedowns(data)
        print("\n--- REGISTRAR TAKEDOWN ---")
        print(result["registrar"]["email_draft"])
        print("\n--- HOSTING TAKEDOWN ---")
        print(result["hosting"]["email_draft"])
