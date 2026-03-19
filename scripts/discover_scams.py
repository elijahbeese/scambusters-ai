"""
discover_scams.py — Autonomous Scam Discovery Engine v2
Scrapes all major HYIP/crypto scam intelligence sources to find
fresh domains without waiting for bounties.

Sources:
1. HYIP Monitor sites (hyipexplorer, goldpoll, hyiplogs, hyipbrowser)
2. URLScan cryptoscam tag feed
3. CryptoScamDB API
4. PhishTank feed
5. OpenPhish feed
6. Telegram public channel monitoring
"""

import os
import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Known non-scam domains to filter out
WHITELIST = {
    "google.com", "facebook.com", "twitter.com", "youtube.com",
    "instagram.com", "linkedin.com", "github.com", "cloudflare.com",
    "amazonaws.com", "microsoft.com", "apple.com", "bitcoin.org",
    "ethereum.org", "binance.com", "coinbase.com", "kraken.com",
    "urlscan.io", "virustotal.com", "shodan.io", "whois.com",
}

# Keywords that strongly indicate HYIP/investment scam
HYIP_KEYWORDS = [
    "stake", "invest", "profit", "yield", "return", "capital",
    "fund", "trade", "crypto", "bitcoin", "earn", "mining",
    "wealth", "finance", "signal", "market", "asset", "coin",
    "token", "defi", "staking", "passive", "income", "roi",
    "hedge", "portfolio", "dividend", "arbitrage", "forex",
]


def clean_domain(url: str) -> str | None:
    """Extract clean domain from URL."""
    try:
        if not url.startswith("http"):
            url = "https://" + url
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.lstrip("www.").strip().lower()
        if "." not in domain or len(domain) < 4:
            return None
        if any(w in domain for w in WHITELIST):
            return None
        return domain
    except Exception:
        return None


def is_likely_scam(domain: str) -> bool:
    """Quick heuristic check if domain looks like HYIP/investment scam."""
    domain_lower = domain.lower()
    return any(kw in domain_lower for kw in HYIP_KEYWORDS)


# ── Source 1: HYIP Monitor Sites ─────────────────────────────────────────────

def scrape_hyipexplorer() -> list:
    """Scrape HYIPExplorer for new listings."""
    domains = []
    try:
        r = requests.get(
            "https://hyipexplorer.com/",
            headers=HEADERS, timeout=20
        )
        soup = BeautifulSoup(r.text, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "hyipexplorer.com" not in href and href.startswith("http"):
                d = clean_domain(href)
                if d and d not in domains:
                    domains.append(d)
        print(f"  [discover] HYIPExplorer: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] HYIPExplorer failed: {e}")
    return domains


def scrape_goldpoll() -> list:
    """Scrape GoldPoll HYIP monitor."""
    domains = []
    try:
        for page in range(1, 4):
            r = requests.get(
                f"https://goldpoll.com/hyip-monitors/?page={page}",
                headers=HEADERS, timeout=20
            )
            soup = BeautifulSoup(r.text, "lxml")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if "goldpoll.com" not in href and href.startswith("http"):
                    d = clean_domain(href)
                    if d and d not in domains:
                        domains.append(d)
            time.sleep(1)
        print(f"  [discover] GoldPoll: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] GoldPoll failed: {e}")
    return domains


def scrape_hyiplogs() -> list:
    """Scrape HYIPLogs monitor."""
    domains = []
    try:
        r = requests.get(
            "https://www.hyiplogs.com/",
            headers=HEADERS, timeout=20
        )
        soup = BeautifulSoup(r.text, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "hyiplogs.com" not in href and href.startswith("http"):
                d = clean_domain(href)
                if d and d not in domains:
                    domains.append(d)
        print(f"  [discover] HYIPLogs: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] HYIPLogs failed: {e}")
    return domains


def scrape_hyipbrowser() -> list:
    """Scrape HYIPBrowser monitor."""
    domains = []
    try:
        r = requests.get(
            "https://www.hyipbrowser.com/",
            headers=HEADERS, timeout=20
        )
        soup = BeautifulSoup(r.text, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "hyipbrowser.com" not in href and href.startswith("http"):
                d = clean_domain(href)
                if d and d not in domains:
                    domains.append(d)
        print(f"  [discover] HYIPBrowser: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] HYIPBrowser failed: {e}")
    return domains


def scrape_hyiprating() -> list:
    """Scrape HYIP Rating monitor."""
    domains = []
    try:
        r = requests.get(
            "https://hyiprating.com/",
            headers=HEADERS, timeout=20
        )
        soup = BeautifulSoup(r.text, "lxml")
        # Look for program links
        for a in soup.select("a.program-link, a.hyip-link, td a[href*='http']"):
            href = a.get("href", "")
            if "hyiprating.com" not in href and href.startswith("http"):
                d = clean_domain(href)
                if d and d not in domains:
                    domains.append(d)
        print(f"  [discover] HYIPRating: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] HYIPRating failed: {e}")
    return domains


# ── Source 2: URLScan Cryptoscam Tag ─────────────────────────────────────────

def scrape_urlscan_cryptoscam(limit: int = 100) -> list:
    """
    Query URLScan for domains tagged as cryptoscam.
    This is the most reliable source — community-verified.
    """
    domains = []
    if not URLSCAN_KEY:
        print("  [discover] URLScan: no API key")
        return domains

    try:
        queries = [
            "tag:cryptoscam",
            "tag:hyip",
            "tag:investmentscam",
            "tag:cryptofraud",
            "page.title:invest* AND page.title:crypto*",
        ]

        for query in queries:
            r = requests.get(
                f"https://urlscan.io/api/v1/search/?q={query}&size=100",
                headers={
                    "User-Agent": "ScamBusters-Agent/2.0",
                    "API-Key": URLSCAN_KEY,
                },
                timeout=20
            )
            if r.status_code == 200:
                results = r.json().get("results", [])
                for result in results:
                    domain = result.get("page", {}).get("domain", "")
                    if domain:
                        d = clean_domain(domain)
                        if d and d not in domains:
                            domains.append(d)
            time.sleep(0.5)

        print(f"  [discover] URLScan cryptoscam: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] URLScan failed: {e}")

    return domains


# ── Source 3: CryptoScamDB ────────────────────────────────────────────────────

def scrape_cryptoscamdb() -> list:
    """
    Query CryptoScamDB for known scam domains.
    Free API, no key required.
    """
    domains = []
    try:
        r = requests.get(
            "https://cryptoscamdb.org/api/scams",
            headers=HEADERS, timeout=20
        )
        if r.status_code == 200:
            data = r.json()
            scams = data.get("result", {}).get("scams", [])
            for scam in scams:
                url = scam.get("url", "")
                if url:
                    d = clean_domain(url)
                    if d and d not in domains:
                        domains.append(d)
        print(f"  [discover] CryptoScamDB: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] CryptoScamDB failed: {e}")
    return domains


# ── Source 4: PhishTank ───────────────────────────────────────────────────────

def scrape_phishtank() -> list:
    """
    Query PhishTank for crypto-related phishing/scam URLs.
    Free, no key required for basic access.
    """
    domains = []
    try:
        # PhishTank provides a daily dump
        r = requests.get(
            "https://data.phishtank.com/data/online-valid.json.gz",
            headers=HEADERS, timeout=30, stream=True
        )
        if r.status_code == 200:
            import gzip
            import json
            content = gzip.decompress(r.content)
            phishes = json.loads(content)
            for phish in phishes:
                url = phish.get("url", "")
                target = phish.get("target", "").lower()
                # Only grab crypto-related phishes
                if any(kw in target for kw in ["crypto", "bitcoin", "ethereum", "binance", "coinbase"]):
                    d = clean_domain(url)
                    if d and d not in domains:
                        domains.append(d)
        print(f"  [discover] PhishTank: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] PhishTank failed: {e}")
    return domains


def scrape_openphish() -> list:
    """
    Query OpenPhish community feed.
    Free, no auth required.
    """
    domains = []
    try:
        r = requests.get(
            "https://openphish.com/feed.txt",
            headers=HEADERS, timeout=20
        )
        if r.status_code == 200:
            for line in r.text.strip().split("\n"):
                url = line.strip()
                if url:
                    d = clean_domain(url)
                    if d and d not in domains and is_likely_scam(d):
                        domains.append(d)
        print(f"  [discover] OpenPhish: {len(domains)} domains")
    except Exception as e:
        print(f"  [discover] OpenPhish failed: {e}")
    return domains


# ── Source 5: Telegram Channel Monitoring ─────────────────────────────────────

def scrape_telegram_channels() -> list:
    """
    Scrape public Telegram channels known to advertise HYIP/crypto scams.
    Uses Telegram's web preview (no API key needed for public channels).
    
    Known scam-promoting channels:
    - @hyipinvestments
    - @cryptohyip
    - @hyipnews
    - @investmentscam (monitor/warning channels)
    """
    domains = []
    channels = [
        "hyipinvestments",
        "cryptohyip",
        "hyipnews",
        "hyip_monitor",
        "cryptoinvestnews",
        "hyipreview",
        "newcryptoprojects",
        "cryptostaking_news",
    ]

    for channel in channels:
        try:
            r = requests.get(
                f"https://t.me/s/{channel}",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                # Extract URLs from Telegram preview
                urls = re.findall(
                    r'href="(https?://(?!t\.me|telegram\.org)[^"]+)"',
                    r.text
                )
                for url in urls:
                    d = clean_domain(url)
                    if d and d not in domains:
                        domains.append(d)
            time.sleep(1)
        except Exception:
            continue

    print(f"  [discover] Telegram channels: {len(domains)} domains")
    return domains


# ── Main discovery function ───────────────────────────────────────────────────

def discover_scam_domains(max_domains: int = 200,
                          urlscan_api_key: str = "") -> list:
    """
    Run all discovery sources and return deduplicated list of scam domains.
    """
    if urlscan_api_key:
        global URLSCAN_KEY
        URLSCAN_KEY = urlscan_api_key

    all_domains = []

    print("\n[discover] Starting autonomous scam discovery...")

    sources = [
        ("HYIP Explorer",   scrape_hyipexplorer),
        ("GoldPoll",        scrape_goldpoll),
        ("HYIPLogs",        scrape_hyiplogs),
        ("HYIPBrowser",     scrape_hyipbrowser),
        ("HYIPRating",      scrape_hyiprating),
        ("URLScan",         scrape_urlscan_cryptoscam),
        ("CryptoScamDB",    scrape_cryptoscamdb),
        ("OpenPhish",       scrape_openphish),
        ("PhishTank",       scrape_phishtank),
        ("Telegram",        scrape_telegram_channels),
    ]

    for name, func in sources:
        try:
            found = func()
            new = [d for d in found if d not in all_domains]
            all_domains.extend(new)
            print(f"  [discover] {name}: +{len(new)} new ({len(all_domains)} total)")
        except Exception as e:
            print(f"  [discover] {name} error: {e}")

    # Filter and deduplicate
    all_domains = list(set(all_domains))

    # Prioritize domains with HYIP keywords in the name
    priority = [d for d in all_domains if is_likely_scam(d)]
    other    = [d for d in all_domains if not is_likely_scam(d)]

    # Return priority first, capped at max_domains
    result = (priority + other)[:max_domains]

    print(f"\n[discover] Total: {len(result)} domains ({len(priority)} high-priority)")
    return result


if __name__ == "__main__":
    domains = discover_scam_domains(max_domains=50)
    print("\nTop domains found:")
    for d in domains[:20]:
        print(f"  {d}")
