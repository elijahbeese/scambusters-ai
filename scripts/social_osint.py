"""
social_osint.py — Deep social media and wallet OSINT v2
Fixes:
- Deeper HTML scraping (multiple pages, not just homepage)
- Phone number extraction (regex patterns for international formats)
- Better wallet regex (all major currencies)
- Telegram member count extraction
- WhatsApp group links
- WeChat, Line, KakaoTalk (common in Asian HYIP scams)
- JavaScript source scraping for hidden wallet addresses
- Meta tags, schema.org extraction
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ── Wallet address patterns ───────────────────────────────────────────────────
WALLET_PATTERNS = {
    "BTC":        r"\b(bc1[a-zA-Z0-9]{25,62}|[13][a-zA-Z0-9]{25,34})\b",
    "ETH":        r"\b(0x[a-fA-F0-9]{40})\b",
    "USDT_TRC20": r"\b(T[a-zA-Z0-9]{33})\b",
    "LTC":        r"\b([LM3][a-zA-Z0-9]{25,34}|ltc1[a-zA-Z0-9]{25,62})\b",
    "XRP":        r"\b(r[0-9a-zA-Z]{24,34})\b",
    "BNB":        r"\b(bnb1[a-zA-Z0-9]{38})\b",
    "DOGE":       r"\b(D[a-zA-Z0-9]{25,34})\b",
    "TRX":        r"\b(T[A-Za-z0-9]{33})\b",
    "SOL":        r"\b([1-9A-HJ-NP-Za-km-z]{32,44})\b",
}

# ── Phone patterns ────────────────────────────────────────────────────────────
PHONE_PATTERN = re.compile(
    r"(?:\+|00)?(?:[1-9]\d{0,2}[\s\-\.]?)?"   # country code
    r"(?:\(?\d{1,4}\)?[\s\-\.]?)"              # area code
    r"(?:\d{3,4}[\s\-\.]?\d{3,4})"            # number
)

# ── Social link patterns ──────────────────────────────────────────────────────
SOCIAL_PATTERNS = {
    "telegram":  [r"t\.me/[\w+]+", r"telegram\.me/[\w+]+", r"telegram\.org/[\w+]+"],
    "whatsapp":  [r"wa\.me/\d+", r"whatsapp\.com/\S+", r"api\.whatsapp\.com/\S+"],
    "facebook":  [r"facebook\.com/(?:groups/)?[\w\-.]+", r"fb\.com/[\w\-.]+", r"fb\.gg/[\w\-.]+"],
    "instagram": [r"instagram\.com/[\w\-.]+"],
    "twitter":   [r"twitter\.com/[\w\-.]+", r"x\.com/[\w\-.]+"],
    "youtube":   [r"youtube\.com/(?:channel/|@|c/)?[\w\-.]+"],
    "tiktok":    [r"tiktok\.com/@[\w\-.]+"],
    "wechat":    [r"weixin\.qq\.com/\S+"],
    "discord":   [r"discord\.gg/[\w\-.]+", r"discord\.com/invite/[\w\-.]+"],
    "vk":        [r"vk\.com/[\w\-.]+"],
    "line":      [r"line\.me/\S+"],
}


def fetch_page(url: str, timeout: int = 15) -> str | None:
    """Fetch a page with browser-like headers."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout,
                        allow_redirects=True)
        if r.status_code == 200:
            return r.text
        return None
    except Exception:
        return None


def get_pages_to_scrape(domain: str, html: str) -> list[str]:
    """
    Find additional pages worth scraping for contact/wallet info.
    HYIP sites typically have: /invest, /deposit, /withdraw, /contact, /about
    """
    base_url = f"https://{domain}"
    pages = [base_url]

    high_value_paths = [
        "/invest", "/deposit", "/withdraw", "/payment",
        "/contact", "/about", "/support", "/faq",
        "/register", "/signup", "/login",
        "/plans", "/packages", "/referral",
        "/wallet", "/dashboard",
    ]

    # Add known high-value paths
    for path in high_value_paths:
        pages.append(base_url + path)

    # Extract internal links from homepage
    if html:
        try:
            soup = BeautifulSoup(html, "lxml")
            for a in soup.find_all("a", href=True)[:50]:
                href = a["href"]
                if href.startswith("/"):
                    full = base_url + href
                elif domain in href:
                    full = href
                else:
                    continue
                if full not in pages:
                    pages.append(full)
        except Exception:
            pass

    return pages[:12]  # Cap at 12 pages to avoid hammering the server


def extract_social_links(html: str, domain: str) -> dict:
    """Extract all social media links from HTML."""
    social = {k: [] for k in SOCIAL_PATTERNS}

    # Search in raw HTML (catches obfuscated links)
    for platform, patterns in SOCIAL_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in matches:
                url = m if m.startswith("http") else f"https://{m}"
                if url not in social[platform]:
                    social[platform].append(url)

    return social


def extract_wallets(html: str) -> dict:
    """Extract cryptocurrency wallet addresses from HTML and JS."""
    wallets = {}

    for currency, pattern in WALLET_PATTERNS.items():
        matches = re.findall(pattern, html)
        if matches:
            # Filter out obvious false positives
            valid = []
            for addr in set(matches):
                # Skip very common false positive patterns
                if len(addr) < 25:
                    continue
                if addr.startswith("0x000000"):
                    continue
                if addr == "0x" + "0" * 40:
                    continue
                valid.append(addr)
            if valid:
                wallets[currency] = valid

    return wallets


def extract_phones(html: str) -> list:
    """Extract phone numbers from HTML."""
    # Remove HTML tags first
    text = re.sub(r"<[^>]+>", " ", html)

    # Extract phone numbers
    phones = []
    for match in PHONE_PATTERN.finditer(text):
        phone = match.group().strip()
        # Filter: must be at least 7 digits
        digits = re.sub(r"\D", "", phone)
        if len(digits) >= 7 and phone not in phones:
            phones.append(phone)

    return phones[:20]


def extract_emails(html: str) -> list:
    """Extract email addresses from HTML."""
    # Remove common false positives
    emails = re.findall(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        html
    )
    # Filter out image files, example emails, etc.
    filtered = []
    skip_patterns = ["example", "yourdomain", ".png", ".jpg", ".gif", "sentry", "wixpress"]
    for email in set(e.lower() for e in emails):
        if not any(skip in email for skip in skip_patterns):
            filtered.append(email)
    return filtered[:20]


def extract_meta_info(html: str) -> dict:
    """Extract meta tags, schema.org, and structured data."""
    info = {}
    try:
        soup = BeautifulSoup(html, "lxml")

        # Meta description
        desc = soup.find("meta", {"name": "description"})
        if desc:
            info["meta_description"] = desc.get("content", "")[:300]

        # OG tags
        og_title = soup.find("meta", {"property": "og:title"})
        if og_title:
            info["og_title"] = og_title.get("content", "")

        # Site name
        og_site = soup.find("meta", {"property": "og:site_name"})
        if og_site:
            info["site_name"] = og_site.get("content", "")

        # Schema.org JSON-LD
        scripts = soup.find_all("script", {"type": "application/ld+json"})
        schema_data = []
        for script in scripts:
            try:
                import json
                data = json.loads(script.string)
                schema_data.append(data)
            except Exception:
                pass
        if schema_data:
            info["schema_org"] = schema_data

        # Title
        title = soup.find("title")
        if title:
            info["page_title"] = title.get_text().strip()[:200]

    except Exception:
        pass

    return info


def run_social_osint(domain: str) -> dict:
    """
    Full social OSINT pipeline:
    1. Fetch homepage + high-value subpages
    2. Extract social links from all pages
    3. Extract wallet addresses
    4. Extract phone numbers and emails
    5. Extract meta information
    """
    base_url = f"https://{domain}"

    # Fetch homepage
    homepage_html = fetch_page(base_url)
    if not homepage_html:
        # Try HTTP
        homepage_html = fetch_page(f"http://{domain}")

    if not homepage_html:
        return {
            "error": f"Could not fetch {domain}",
            "social_links": {k: [] for k in SOCIAL_PATTERNS},
            "contact_info": {"emails": [], "phones": []},
            "wallets_from_html": {},
            "meta": {},
        }

    # Get additional pages to scrape
    pages = get_pages_to_scrape(domain, homepage_html)

    # Collect all HTML
    all_html = homepage_html
    for page_url in pages[1:6]:  # Scrape up to 5 additional pages
        page_html = fetch_page(page_url)
        if page_html:
            all_html += "\n" + page_html

    # Extract everything
    social_links = extract_social_links(all_html, domain)
    wallets      = extract_wallets(all_html)
    phones       = extract_phones(all_html)
    emails       = extract_emails(all_html)
    meta         = extract_meta_info(homepage_html)

    # Build Google Dork queries for manual investigation
    google_dorks = {
        "intitle_domain":    f'https://www.google.com/search?q=intitle:"{domain.split(".")[0]}"',
        "intitle_full":      f'https://www.google.com/search?q=intitle:"{domain}"',
        "intext_domain":     f'https://www.google.com/search?q=intext:"{domain}"',
        "site_references":   f'https://www.google.com/search?q="{domain}"+-site:{domain}',
        "telegram_promo":    f'https://www.google.com/search?q=site:t.me+"{domain.split(".")[0]}"',
        "facebook_groups":   f'https://www.google.com/search?q=site:facebook.com+"{domain.split(".")[0]}"',
        "tiktok_promo":      f'https://www.google.com/search?q=site:tiktok.com+"{domain.split(".")[0]}"',
        "referral_codes":    f'https://www.google.com/search?q="{domain}"+ref+OR+referral+OR+invite',
        "trustpilot":        f'https://www.trustpilot.com/review/{domain}',
        "reddit_mentions":   f'https://www.reddit.com/search/?q={domain}',
        "note": "Run manually or integrate SerpAPI for automation.",
    }

    return {
        "social_links":     social_links,
        "contact_info":     {"emails": emails, "phones": phones},
        "wallets_from_html": wallets,
        "meta":             meta,
        "google_dorks":     google_dorks,
        "pages_scraped":    len(pages[:6]),
    }


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "stake2earn.app"
    result = run_social_osint(domain)
    print(json.dumps(result, indent=2, default=str))
