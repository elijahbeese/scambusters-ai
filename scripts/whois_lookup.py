"""
whois_lookup.py — Robust WHOIS + SOA email extraction v2
Fixes:
- Multi-format WHOIS parsing (python-whois fails on many TLDs)
- Fallback to raw WHOIS socket query
- SOA email via dig (system call)
- Registrar abuse email extraction from IANA lookup
- Handles Namecheap, NICENIC, GoDaddy, Cloudflare and other common registrars
"""

import os
import re
import subprocess
import requests
import whois as pywhois
from dotenv import load_dotenv

load_dotenv()

HEADERS = {"User-Agent": "ScamBusters-Agent/2.0 OSINT-Investigation"}


def run_whois(domain: str) -> dict:
    """
    Multi-method WHOIS lookup with fallbacks.
    Returns structured registrar, dates, contacts, SOA email.
    """
    result = {
        "domain":               domain,
        "registrar":            None,
        "creation_date":        None,
        "expiration_date":      None,
        "updated_date":         None,
        "registrar_abuse_email": None,
        "registrar_abuse_phone": None,
        "name_servers":         [],
        "registrant_country":   None,
        "registrant_org":       None,
        "registrant_name":      None,
        "org":                  None,
        "soa_email":            None,
        "raw_emails":           [],
        "privacy_protected":    False,
    }

    # Method 1: python-whois
    try:
        w = pywhois.whois(domain)
        if w:
            result["registrar"]        = _clean(w.registrar)
            result["creation_date"]    = _first_date(w.creation_date)
            result["expiration_date"]  = _first_date(w.expiration_date)
            result["updated_date"]     = _first_date(w.updated_date)
            result["name_servers"]     = _clean_ns(w.name_servers)
            result["registrant_country"] = _clean(w.country)
            result["registrant_org"]   = _clean(w.org)
            result["registrant_name"]  = _clean(w.name)
            result["org"]              = _clean(w.org)

            # Extract all emails
            emails = []
            if w.emails:
                emails = [e.lower() for e in (w.emails if isinstance(w.emails, list) else [w.emails])]
            result["raw_emails"] = emails

            # Identify abuse email
            for email in emails:
                if any(kw in email for kw in ["abuse", "support", "admin", "legal"]):
                    result["registrar_abuse_email"] = email
                    break
            if not result["registrar_abuse_email"] and emails:
                result["registrar_abuse_email"] = emails[0]

            # Check privacy protection
            raw = str(w).lower()
            if any(kw in raw for kw in ["redacted", "privacy", "protected", "withheld"]):
                result["privacy_protected"] = True

    except Exception as e:
        print(f"  [whois] python-whois failed: {e}")

    # Method 2: Raw WHOIS via system whois command (more complete)
    try:
        raw = _raw_whois(domain)
        if raw:
            result = _parse_raw_whois(raw, result)
    except Exception as e:
        print(f"  [whois] Raw WHOIS failed: {e}")

    # Method 3: RDAP (Registration Data Access Protocol) — modern standard
    try:
        rdap = _rdap_lookup(domain)
        if rdap:
            result = _merge_rdap(rdap, result)
    except Exception as e:
        print(f"  [whois] RDAP failed: {e}")

    # Method 4: SOA email via dig
    try:
        soa = _get_soa_email(domain)
        if soa:
            result["soa_email"] = soa
    except Exception as e:
        print(f"  [whois] SOA dig failed: {e}")

    # Method 5: Get registrar abuse contact from IANA
    if result["registrar"] and not result["registrar_abuse_email"]:
        try:
            abuse = _get_registrar_abuse(result["registrar"])
            if abuse:
                result["registrar_abuse_email"] = abuse
        except Exception:
            pass

    return result


def _raw_whois(domain: str) -> str:
    """Run system whois command and return raw text."""
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception:
        return ""


def _parse_raw_whois(raw: str, existing: dict) -> dict:
    """Parse raw WHOIS text to fill in missing fields."""
    lines = raw.lower().split("\n")
    raw_lower = raw.lower()

    field_map = {
        "registrar:":           "registrar",
        "registrar name:":      "registrar",
        "sponsoring registrar:": "registrar",
        "registrant country:":  "registrant_country",
        "country:":             "registrant_country",
        "registrant organization:": "registrant_org",
        "registrant org:":      "registrant_org",
        "org:":                 "org",
        "registrant name:":     "registrant_name",
        "name:":                "registrant_name",
    }

    for line in raw.split("\n"):
        line_lower = line.lower().strip()
        for key, field in field_map.items():
            if line_lower.startswith(key):
                value = line[len(key):].strip()
                if value and not existing.get(field):
                    existing[field] = value
                break

    # Extract all emails from raw
    emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw)
    emails = list(set(e.lower() for e in emails))
    if emails:
        existing["raw_emails"] = list(set(existing.get("raw_emails", []) + emails))
        # Find abuse email
        for email in emails:
            if "abuse" in email and not existing.get("registrar_abuse_email"):
                existing["registrar_abuse_email"] = email

    # Parse name servers
    ns_pattern = re.findall(r"name server:\s*(\S+)", raw_lower)
    if ns_pattern and not existing.get("name_servers"):
        existing["name_servers"] = [ns.upper() for ns in ns_pattern]

    # Parse dates if missing
    if not existing.get("creation_date"):
        for pattern in [
            r"creation date:\s*(.+)",
            r"created:\s*(.+)",
            r"registered:\s*(.+)",
        ]:
            match = re.search(pattern, raw_lower)
            if match:
                existing["creation_date"] = match.group(1).strip()
                break

    if not existing.get("expiration_date"):
        for pattern in [
            r"expir\w* date:\s*(.+)",
            r"expiry date:\s*(.+)",
            r"expires:\s*(.+)",
        ]:
            match = re.search(pattern, raw_lower)
            if match:
                existing["expiration_date"] = match.group(1).strip()
                break

    # Registrar abuse phone
    phone_match = re.search(
        r"registrar abuse contact phone:\s*(.+)", raw_lower
    )
    if phone_match and not existing.get("registrar_abuse_phone"):
        existing["registrar_abuse_phone"] = phone_match.group(1).strip()

    return existing


def _rdap_lookup(domain: str) -> dict | None:
    """RDAP lookup via ARIN/ICANN — more structured than WHOIS."""
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers=HEADERS, timeout=15
        )
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def _merge_rdap(rdap: dict, existing: dict) -> dict:
    """Merge RDAP data into existing result."""
    # Registrar
    for entity in rdap.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        if "registrar" in roles and not existing.get("registrar"):
            fn = _extract_vcard_fn(vcard)
            if fn:
                existing["registrar"] = fn
        if "abuse" in roles:
            email = _extract_vcard_email(vcard)
            phone = _extract_vcard_phone(vcard)
            if email and not existing.get("registrar_abuse_email"):
                existing["registrar_abuse_email"] = email
            if phone and not existing.get("registrar_abuse_phone"):
                existing["registrar_abuse_phone"] = phone

    # Dates
    for event in rdap.get("events", []):
        action = event.get("eventAction", "")
        date   = event.get("eventDate", "")
        if action == "registration" and not existing.get("creation_date"):
            existing["creation_date"] = date
        elif action == "expiration" and not existing.get("expiration_date"):
            existing["expiration_date"] = date

    # Name servers
    if not existing.get("name_servers"):
        ns = [ns.get("ldhName", "") for ns in rdap.get("nameservers", [])]
        if ns:
            existing["name_servers"] = ns

    return existing


def _extract_vcard_fn(vcard: list) -> str | None:
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4:
            if item[0] == "fn":
                return item[3]
    return None


def _extract_vcard_email(vcard: list) -> str | None:
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4:
            if item[0] == "email":
                return item[3]
    return None


def _extract_vcard_phone(vcard: list) -> str | None:
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4:
            if item[0] == "tel":
                return item[3]
    return None


def _get_soa_email(domain: str) -> str | None:
    """
    Get SOA email record via dig.
    The SOA email is the key threat actor pivot — same email = same operator.
    Format: hostmaster@domain.com → dig returns hostmaster.domain.com
    """
    try:
        result = subprocess.run(
            ["dig", "SOA", domain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        if not output:
            return None

        # Parse SOA record: "ns1.domain.com. email.domain.com. serial refresh..."
        parts = output.split()
        if len(parts) >= 2:
            # Convert dig SOA email format (dots to @)
            email_part = parts[1].rstrip(".")
            # Last dot before TLD is the @ separator
            # e.g. "hostmaster.registrar-servers.com" → "hostmaster@registrar-servers.com"
            email_parts = email_part.split(".")
            if len(email_parts) >= 3:
                local = email_parts[0]
                domain_part = ".".join(email_parts[1:])
                return f"{local}@{domain_part}"
        return None
    except Exception:
        return None


def _get_registrar_abuse(registrar_name: str) -> str | None:
    """
    Look up known registrar abuse contacts.
    """
    known = {
        "namecheap":    "abuse@namecheap.com",
        "godaddy":      "abuse@godaddy.com",
        "cloudflare":   "abuse@cloudflare.com",
        "nicenic":      "abuse@nicenic.net",
        "namesilo":     "abuse@namesilo.com",
        "porkbun":      "abuse@porkbun.com",
        "cosmotown":    "abuse@cosmotown.com",
        "tucows":       "domainabuse@tucows.com",
        "enom":         "abuse@enom.com",
        "network solutions": "abuse@networksolutions.com",
        "web.com":      "abuse@web.com",
        "registrar-servers": "abuse@namecheap.com",  # Namecheap uses this
        "webnic":       "abuse@webnic.cc",
        "internet.bs":  "abuse@internet.bs",
        "dynadot":      "abuse@dynadot.com",
    }

    registrar_lower = registrar_name.lower()
    for key, email in known.items():
        if key in registrar_lower:
            return email
    return None


def _clean(val) -> str | None:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val).strip() if val else None


def _first_date(val):
    if val is None:
        return None
    if isinstance(val, list):
        return val[0]
    return val


def _clean_ns(ns) -> list:
    if not ns:
        return []
    if isinstance(ns, str):
        ns = [ns]
    return [str(n).upper().rstrip(".") for n in ns if n]


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "stake2earn.app"
    result = run_whois(domain)
    print(json.dumps(result, indent=2, default=str))
