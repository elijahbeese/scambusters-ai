"""
Stage 1: discover_scams.py
Scrapes HYIP monitoring sites to extract live crypto investment scam domains.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time
import random

# HYIP monitoring sites — all fraudulent, all useful
HYIP_MONITORS = [
    "https://www.tophyip.biz/",
    "https://bestemoneys.com/hyips_1.html",
    "https://phyip.com/",
    "https://hyipbanker.com/",
    "https://www.hothyips.com/",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


def extract_domains_from_monitor(url: str) -> list[str]:
    """
    Scrape a HYIP monitor page and extract external scam site domains.
    Returns a list of base domains.
    """
    domains = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, "lxml")

        for a in soup.find_all("a", href=True):
            href = a["href"]
            parsed = urlparse(href)

            # We want external links that look like investment sites
            if parsed.scheme in ("http", "https") and parsed.netloc:
                monitor_domain = urlparse(url).netloc
                link_domain = parsed.netloc.replace("www.", "")

                # Skip links back to the monitor site itself
                if monitor_domain in link_domain:
                    continue

                # Skip common non-scam domains
                skip = ["google.", "facebook.", "twitter.", "t.me", "telegram."]
                if any(s in link_domain for s in skip):
                    continue

                if link_domain and link_domain not in domains:
                    domains.append(link_domain)

    except Exception as e:
        print(f"      [!] Failed to scrape {url}: {e}")

    return domains


def discover_scam_domains(max_domains: int = 20) -> list[str]:
    """
    Scrape all configured HYIP monitors and return a deduplicated
    list of scam domains, capped at max_domains.
    """
    all_domains = []

    for monitor in HYIP_MONITORS:
        print(f"      Scraping: {monitor}")
        domains = extract_domains_from_monitor(monitor)
        all_domains.extend(domains)
        # Be polite — don't hammer monitors
        time.sleep(random.uniform(1.5, 3.0))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for d in all_domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)

    return unique[:max_domains]


if __name__ == "__main__":
    domains = discover_scam_domains(max_domains=10)
    print(f"\nDiscovered {len(domains)} domains:")
    for d in domains:
        print(f"  {d}")
