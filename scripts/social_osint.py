"""
Stage 5: social_osint.py
Extracts social media links, Telegram/WhatsApp channels, and
runs Google Dork queries to find promotional content.
"""

import requests
from bs4 import BeautifulSoup
import time
import re

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

SOCIAL_PATTERNS = {
    "telegram": r"https?://(t\.me|telegram\.me)/\S+",
    "whatsapp": r"https?://chat\.whatsapp\.com/\S+",
    "facebook": r"https?://(www\.)?facebook\.com/\S+",
    "instagram": r"https?://(www\.)?instagram\.com/\S+",
    "twitter": r"https?://(www\.)?twitter\.com/\S+",
    "youtube": r"https?://(www\.)?youtube\.com/\S+",
}


def scrape_scam_site_links(domain: str) -> dict:
    """
    Visit the scam site's homepage and contact page to extract
    social media links and contact info.
    """
    found = {platform: [] for platform in SOCIAL_PATTERNS}
    found["emails"] = []
    found["phone_numbers"] = []

    pages_to_check = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/contact-us",
        f"https://{domain}/support",
    ]

    for url in pages_to_check:
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            text = r.text

            # Extract social links
            for platform, pattern in SOCIAL_PATTERNS.items():
                matches = re.findall(pattern, text)
                found[platform].extend(matches)

            # Extract emails
            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
            found["emails"].extend(emails)

            # Extract phone numbers (rough pattern)
            phones = re.findall(r"\+?[\d\s\-\(\)]{10,20}", text)
            found["phone_numbers"].extend([p.strip() for p in phones if len(p.strip()) >= 10])

            time.sleep(1)

        except Exception:
            continue

    # Deduplicate
    for key in found:
        found[key] = list(set(found[key]))

    return found


def google_dork(domain: str) -> dict:
    """
    Build Google Dork URLs for intitle: and intext: queries.
    We return the query URLs rather than scraping Google directly
    (scraping Google violates ToS and gets you rate-limited fast).
    Investigators should run these manually or via SerpAPI.
    """
    # Extract site name without TLD for cleaner queries
    site_name = domain.split(".")[0]

    dorks = {
        "intitle": f'https://www.google.com/search?q=intitle:"{site_name}"',
        "intext": f'https://www.google.com/search?q=intext:"{domain}"',
        "site_references": f'https://www.google.com/search?q="{domain}"+-site:{domain}',
        "telegram_promo": f'https://www.google.com/search?q=site:t.me+"{site_name}"',
        "facebook_promo": f'https://www.google.com/search?q=site:facebook.com+"{site_name}"',
    }

    return {
        "dork_queries": dorks,
        "note": "Run these queries manually or integrate SerpAPI for automated results.",
    }


def run_social_osint(domain: str) -> dict:
    """Combined social OSINT + dork query generation."""
    site_links = scrape_scam_site_links(domain)
    dorks = google_dork(domain)

    return {
        "social_links": site_links,
        "google_dorks": dorks,
    }


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_social_osint(domain)
    print(json.dumps(result, indent=2))
