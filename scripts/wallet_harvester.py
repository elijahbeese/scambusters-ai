"""
wallet_harvester.py — Headless browser wallet extraction
Uses Playwright to:
1. Create a fake account on HYIP scam sites
2. Navigate to deposit/invest/payment pages
3. Extract all cryptocurrency wallet addresses
4. Screenshot evidence of the deposit page

This automates the manual step from I4G curriculum Section 1:
"Creating Fake Accounts on Cryptoscam Sites"

OpSec notes:
- Always run behind VPN
- Uses randomized fake identity
- Clears cookies/storage between runs
- Takes screenshots as evidence
"""

import os
import re
import json
import random
import string
import asyncio
from datetime import datetime
from pathlib import Path

WALLET_PATTERNS = {
    "BTC":        r"\b(bc1[a-zA-Z0-9]{25,62}|[13][a-zA-Z0-9]{25,34})\b",
    "ETH":        r"\b(0x[a-fA-F0-9]{40})\b",
    "USDT_TRC20": r"\b(T[A-Za-z0-9]{33})\b",
    "LTC":        r"\b(ltc1[a-zA-Z0-9]{25,62}|[LM][a-zA-Z0-9]{26,33})\b",
    "XRP":        r"\b(r[0-9a-zA-Z]{24,34})\b",
    "DOGE":       r"\b(D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{24,33})\b",
    "SOL":        r"\b([1-9A-HJ-NP-Za-km-z]{43,44})\b",
    "BNB":        r"\b(bnb1[a-zA-Z0-9]{38})\b",
}

# Known false positive patterns — error messages, JS identifiers, etc.
FALSE_POSITIVE_PATTERNS = [
    r"^[A-Z][a-z]+[A-Z]",        # CamelCase = JS class/exception names
    r"Exception$",                 # Error class names
    r"Error$",
    r"Handler$",
    r"Controller$",
    r"resuming",
    r"^[a-z]+[A-Z][a-z]+[A-Z]",  # lowerCamelCase = JS variables
]

DEPOSIT_PATHS = [
    "/deposit", "/invest", "/payment", "/withdraw",
    "/user/deposit", "/user/invest", "/user/payment",
    "/dashboard/deposit", "/dashboard/invest",
    "/account/deposit", "/wallet/deposit",
    "/plans", "/packages", "/invest/plans",
    "/crypto/deposit", "/fund/deposit",
]

REGISTER_PATHS = [
    "/register", "/signup", "/sign-up",
    "/user/register", "/account/register",
    "/auth/register", "/join", "/create-account",
]


def generate_fake_identity() -> dict:
    first_names = ["James", "Michael", "Robert", "David", "John",
                   "Sarah", "Emma", "Lisa", "Anna", "Maria"]
    last_names  = ["Smith", "Johnson", "Williams", "Brown", "Jones",
                   "Garcia", "Miller", "Davis", "Wilson", "Taylor"]
    first = random.choice(first_names)
    last  = random.choice(last_names)
    username = f"{first.lower()}{last.lower()}{random.randint(100,999)}"
    email    = f"{username}@mailinator.com"
    chars    = string.ascii_letters + string.digits + "!@#"
    password = "".join(random.choices(chars, k=14))
    return {
        "first_name": first,
        "last_name":  last,
        "username":   username,
        "email":      email,
        "password":   password,
        "phone":      f"+1{random.randint(2000000000, 9999999999)}",
    }


def extract_wallets_from_text(text: str) -> dict:
    wallets = {}
    for currency, pattern in WALLET_PATTERNS.items():
        matches = re.findall(pattern, text)
        valid = []
        for addr in set(matches):
            # Length check
            if len(addr) < 25:
                continue
            # ETH zero address
            if addr.startswith("0x" + "0" * 38):
                continue
            # Check against false positive patterns
            is_fp = False
            for fp in FALSE_POSITIVE_PATTERNS:
                if re.search(fp, addr):
                    is_fp = True
                    break
            if is_fp:
                continue
            # XRP: must contain numbers
            if currency == "XRP" and not any(c.isdigit() for c in addr):
                continue
            # LTC: must not be all letters
            if currency == "LTC" and addr.isalpha():
                continue
            valid.append(addr)
        if valid:
            wallets[currency] = valid
    return wallets


def _merge_wallets(target: dict, source: dict):
    for currency, addresses in source.items():
        if currency not in target:
            target[currency] = []
        for addr in addresses:
            if addr not in target[currency]:
                target[currency].append(addr)


async def _attempt_registration(page, identity: dict):
    field_selectors = {
        "email": [
            'input[type="email"]', 'input[name="email"]',
            'input[name="user_email"]', 'input[placeholder*="email" i]',
        ],
        "password": [
            'input[type="password"]', 'input[name="password"]',
            'input[name="pass"]', 'input[placeholder*="password" i]',
        ],
        "username": [
            'input[name="username"]', 'input[name="user_name"]',
            'input[name="login"]', 'input[placeholder*="username" i]',
        ],
        "first_name": [
            'input[name="first_name"]', 'input[name="firstname"]',
            'input[name="fname"]', 'input[placeholder*="first name" i]',
        ],
        "last_name": [
            'input[name="last_name"]', 'input[name="lastname"]',
            'input[name="lname"]', 'input[placeholder*="last name" i]',
        ],
        "phone": [
            'input[type="tel"]', 'input[name="phone"]',
            'input[name="mobile"]', 'input[placeholder*="phone" i]',
        ],
        "confirm_password": [
            'input[name="password_confirmation"]',
            'input[name="confirm_password"]',
            'input[name="password2"]',
            'input[placeholder*="confirm" i]',
        ],
    }

    values = {
        "email":            identity["email"],
        "password":         identity["password"],
        "username":         identity["username"],
        "first_name":       identity["first_name"],
        "last_name":        identity["last_name"],
        "phone":            identity["phone"],
        "confirm_password": identity["password"],
    }

    for field, selectors in field_selectors.items():
        for selector in selectors:
            try:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    await el.fill(values[field])
                    break
            except Exception:
                continue

    # Check terms checkboxes
    try:
        for cb in await page.query_selector_all('input[type="checkbox"]'):
            try:
                if not await cb.is_checked():
                    await cb.check()
            except Exception:
                pass
    except Exception:
        pass

    # Submit
    for selector in [
        'button[type="submit"]', 'input[type="submit"]',
        'button:has-text("Register")', 'button:has-text("Sign Up")',
        'button:has-text("Create Account")', 'button:has-text("Join")',
        'button:has-text("Submit")', '.register-btn',
    ]:
        try:
            btn = await page.query_selector(selector)
            if btn and await btn.is_visible():
                await btn.click()
                await page.wait_for_timeout(3000)
                break
        except Exception:
            continue


async def harvest_wallets(domain: str, output_dir: str = "outputs") -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "error": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            "wallets": {},
        }

    base_url  = f"https://{domain}"
    identity  = generate_fake_identity()
    Path(output_dir).mkdir(exist_ok=True)

    all_wallets           = {}
    screenshots           = []
    pages_visited         = []
    registration_success  = False

    print(f"\n  [harvester] Starting headless browser for {domain}")
    print(f"  [harvester] Fake identity: {identity['email']}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox",
                  "--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # Step 1: Homepage
        try:
            await page.goto(base_url, wait_until="networkidle", timeout=30000)
            content = await page.content()
            _merge_wallets(all_wallets, extract_wallets_from_text(content))
            pages_visited.append(base_url)
            ss = f"{output_dir}/{domain.replace('.','_')}_homepage.png"
            await page.screenshot(path=ss, full_page=True)
            screenshots.append(ss)
            print(f"  [harvester] Homepage loaded")
        except Exception as e:
            print(f"  [harvester] Homepage failed: {e}")

        # Step 2: Find registration page and sign up
        for path in REGISTER_PATHS:
            try:
                r = await page.goto(base_url + path,
                                    wait_until="domcontentloaded", timeout=15000)
                if r and r.status == 200:
                    print(f"  [harvester] Found registration: {path}")
                    await _attempt_registration(page, identity)
                    registration_success = True

                    content = await page.content()
                    _merge_wallets(all_wallets, extract_wallets_from_text(content))

                    ss = f"{output_dir}/{domain.replace('.','_')}_post_register.png"
                    await page.screenshot(path=ss, full_page=True)
                    screenshots.append(ss)
                    break
            except Exception:
                continue

        # Step 3: Hit all deposit paths
        print(f"  [harvester] Scanning {len(DEPOSIT_PATHS)} deposit paths...")
        for path in DEPOSIT_PATHS:
            try:
                r = await page.goto(base_url + path,
                                    wait_until="domcontentloaded", timeout=15000)
                if not r or r.status in (404, 403, 500):
                    continue

                await page.wait_for_timeout(2000)
                content = await page.content()
                wallets = extract_wallets_from_text(content)

                if wallets:
                    _merge_wallets(all_wallets, wallets)
                    pages_visited.append(base_url + path)
                    print(f"  [harvester] WALLETS on {path}: {wallets}")
                    ss = f"{output_dir}/{domain.replace('.','_')}{path.replace('/','_')}.png"
                    await page.screenshot(path=ss, full_page=True)
                    screenshots.append(ss)

                # Flag QR codes for manual follow-up
                qr = await page.query_selector_all(
                    "img[src*='qr' i], img[alt*='qr' i], img[alt*='wallet' i]"
                )
                if qr:
                    print(f"  [harvester] QR code on {path} — manual extraction needed")

            except Exception:
                continue

        await browser.close()

    total = sum(len(v) for v in all_wallets.values())
    print(f"  [harvester] Done — {total} wallets found")

    # Auto-analyze wallets on blockchain
    blockchain_results = {}
    total_usd = 0.0
    if all_wallets:
        print(f"  [harvester] Analyzing wallets on blockchain...")
        try:
            from scripts.blockchain import analyze_wallet
            for currency, addresses in all_wallets.items():
                blockchain_results[currency] = []
                for addr in addresses:
                    result = analyze_wallet(currency, addr)
                    blockchain_results[currency].append(result)
                    usd = result.get("total_received_usd", 0) or 0
                    total_usd += usd
                    if usd > 0:
                        print(f"  [harvester] {currency} {addr[:16]}... → ${usd:,.2f} USD")
        except Exception as e:
            print(f"  [harvester] Blockchain analysis error: {e}")

    if total_usd > 0:
        print(f"  [harvester] TOTAL VICTIM LOSSES: ${total_usd:,.2f} USD")

    return {
        "wallets":                all_wallets,
        "wallet_count":           total,
        "blockchain":             blockchain_results,
        "total_usd":              total_usd,
        "pages_visited":          pages_visited,
        "screenshots":            screenshots,
        "registration_attempted": registration_success,
        "fake_email":             identity["email"],
        "timestamp":              datetime.utcnow().isoformat(),
    }


def harvest_wallets_sync(domain: str, output_dir: str = "outputs") -> dict:
    """Synchronous wrapper for use in agent.py."""
    return asyncio.run(harvest_wallets(domain, output_dir))


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "stake2earn.app"
    result = harvest_wallets_sync(domain)
    print(json.dumps(result, indent=2, default=str))
