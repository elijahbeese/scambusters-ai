"""
wallet_harvester.py — Headless browser wallet extraction v3
Fixed:
- Login verification after registration
- Fallback to direct login attempt
- Wait for dashboard indicators before scanning deposit pages  
- SMS/email verification detection and handling
- Better deposit page detection (looks for actual wallet address elements)
- Proper session cookie persistence
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

FALSE_POSITIVE_PATTERNS = [
    r"^[A-Z][a-z]+[A-Z]",
    r"Exception$",
    r"Error$",
    r"Handler$",
    r"Controller$",
    r"resuming",
    r"^[a-z]+[A-Z][a-z]+[A-Z]",
    r"^[a-zA-Z]+\.[a-zA-Z]+$",  # domain-like strings
]

DEPOSIT_PATHS = [
    "/deposit", "/invest", "/payment", "/withdraw",
    "/user/deposit", "/user/invest", "/user/payment",
    "/dashboard/deposit", "/dashboard/invest",
    "/account/deposit", "/wallet/deposit",
    "/plans", "/packages", "/invest/plans",
    "/crypto/deposit", "/fund/deposit",
    "/user/dashboard", "/dashboard", "/home",
    "/user/home", "/member/deposit",
]

REGISTER_PATHS = [
    "/register", "/signup", "/sign-up",
    "/user/register", "/account/register",
    "/auth/register", "/join", "/create-account",
    "/en/register", "/app/register",
]

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in",
    "/user/login", "/account/login",
    "/auth/login", "/user/signin",
    "/en/login", "/app/login",
]

# Indicators that we're logged in (on dashboard)
LOGIN_SUCCESS_INDICATORS = [
    "dashboard", "logout", "log out", "sign out", "signout",
    "my account", "my profile", "deposit", "withdraw",
    "balance", "portfolio", "investment",
]

# Indicators that registration/login failed
LOGIN_FAIL_INDICATORS = [
    "invalid", "incorrect", "wrong password", "not found",
    "verification required", "verify your email", "confirm your email",
    "activate your account",
]


def generate_fake_identity() -> dict:
    first_names = ["James", "Michael", "Robert", "David", "John",
                   "Sarah", "Emma", "Lisa", "Anna", "Maria",
                   "Thomas", "William", "Richard", "Joseph", "Charles"]
    last_names  = ["Smith", "Johnson", "Williams", "Brown", "Jones",
                   "Garcia", "Miller", "Davis", "Wilson", "Taylor",
                   "Anderson", "Thomas", "Jackson", "White", "Harris"]
    first = random.choice(first_names)
    last  = random.choice(last_names)
    # Use temp-mail style addresses that actually receive mail
    username = f"{first.lower()}{last.lower()}{random.randint(100,999)}"
    email    = f"{username}@mailinator.com"
    chars    = string.ascii_letters + string.digits + "!@#$"
    password = "".join(random.choices(chars, k=12)) + "1Aa!"  # meets most password requirements
    return {
        "first_name": first,
        "last_name":  last,
        "username":   username,
        "email":      email,
        "password":   password,
        "phone":      f"+1{random.randint(2000000000, 9999999999)}",
        "referral":   "",
    }


def extract_wallets_from_text(text: str) -> dict:
    wallets = {}
    for currency, pattern in WALLET_PATTERNS.items():
        matches = re.findall(pattern, text)
        valid = []
        for addr in set(matches):
            if len(addr) < 25:
                continue
            if addr.startswith("0x" + "0" * 38):
                continue
            is_fp = False
            for fp in FALSE_POSITIVE_PATTERNS:
                if re.search(fp, addr):
                    is_fp = True
                    break
            if is_fp:
                continue
            if currency == "XRP" and not any(c.isdigit() for c in addr):
                continue
            if currency == "LTC" and addr.isalpha():
                continue
            # SOL: reject pure hex strings (only 0-9 and a-f)
            # Real Solana addresses use full base58 — must have chars outside hex range
            if currency == "SOL" and not re.search(r'[g-zG-Z]', addr):
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


async def _fill_form_fields(page, identity: dict):
    """Fill registration/login form fields."""
    field_selectors = {
        "email": [
            'input[type="email"]', 'input[name="email"]',
            'input[name="user_email"]', 'input[placeholder*="email" i]',
            'input[id*="email" i]',
        ],
        "password": [
            'input[type="password"]', 'input[name="password"]',
            'input[name="pass"]', 'input[placeholder*="password" i]',
            'input[id*="password" i]',
        ],
        "username": [
            'input[name="username"]', 'input[name="user_name"]',
            'input[name="login"]', 'input[placeholder*="username" i]',
            'input[id*="username" i]',
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
        "referral": [
            'input[name="referral"]', 'input[name="ref"]',
            'input[name="referral_code"]', 'input[placeholder*="referral" i]',
        ],
        "full_name": [
            'input[name="full_name"]', 'input[name="fullname"]',
            'input[name="name"]', 'input[placeholder*="full name" i]',
            'input[placeholder*="your name" i]', 'input[id*="fullname" i]',
        ],
        "confirm_email": [
            'input[name="confirm_email"]', 'input[name="email_confirm"]',
            'input[name="email2"]', 'input[placeholder*="confirm email" i]',
            'input[placeholder*="re-enter email" i]',
        ],
        "btc_wallet": [
            'input[placeholder*="bitcoin wallet" i]',
            'input[placeholder*="btc wallet" i]',
            'input[placeholder*="bitcoin address" i]',
            'input[name*="bitcoin" i]', 'input[name*="btc" i]',
        ],
        "usdt_wallet": [
            'input[placeholder*="usdt" i]', 'input[placeholder*="trc20" i]',
            'input[placeholder*="tether" i]', 'input[name*="usdt" i]',
        ],
        "eth_wallet": [
            'input[placeholder*="ethereum" i]', 'input[placeholder*="eth wallet" i]',
            'input[placeholder*="ethereum address" i]', 'input[name*="eth" i]',
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
        "referral":         identity["referral"],
        "full_name":        f"{identity['first_name']} {identity['last_name']}",
        "confirm_email":    identity["email"],
        "btc_wallet":       "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf6a",
        "usdt_wallet":      "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "eth_wallet":       "0x0000000000000000000000000000000000000001",
    }

    filled = []
    for field, selectors in field_selectors.items():
        for selector in selectors:
            try:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    await el.fill(values[field])
                    filled.append(field)
                    break
            except Exception:
                continue

    # Check all checkboxes (ToS, etc)
    try:
        for cb in await page.query_selector_all('input[type="checkbox"]'):
            try:
                if not await cb.is_checked():
                    await cb.check()
            except Exception:
                pass
    except Exception:
        pass

    return filled


async def _submit_form(page) -> bool:
    """Submit form and return True if clicked."""
    for selector in [
        'button[type="submit"]', 'input[type="submit"]',
        'button:has-text("Register")', 'button:has-text("Sign Up")',
        'button:has-text("Create Account")', 'button:has-text("Join")',
        'button:has-text("Login")', 'button:has-text("Sign In")',
        'button:has-text("Submit")', '.register-btn', '.login-btn',
        '#submit', '#login-btn', '#register-btn',
    ]:
        try:
            btn = await page.query_selector(selector)
            if btn and await btn.is_visible():
                await btn.click()
                return True
        except Exception:
            continue
    return False


async def _check_logged_in(page) -> bool:
    """Check if current page indicates we're logged in."""
    try:
        content = await page.content()
        content_lower = content.lower()
        url = page.url.lower()

        # Must have logout/signout link — that only appears when actually logged in
        # (not just marketing words like "dashboard" on homepage)
        has_logout = any(kw in content_lower for kw in
                         ["logout", "log out", "sign out", "signout"])
        if not has_logout:
            return False

        # Also check URL for dashboard indicators
        if any(kw in url for kw in ["dashboard", "account", "member", "user/home"]):
            return True

        # Check content for authenticated-only indicators
        hit_count = sum(1 for kw in LOGIN_SUCCESS_INDICATORS if kw in content_lower)
        fail_count = sum(1 for kw in LOGIN_FAIL_INDICATORS if kw in content_lower)

        return hit_count >= 2 and fail_count == 0
    except Exception:
        return False


async def _attempt_login(page, base_url: str, identity: dict) -> bool:
    """Try to log in with existing credentials."""
    for path in LOGIN_PATHS:
        try:
            r = await page.goto(base_url + path,
                                wait_until="domcontentloaded", timeout=15000)
            if not r or r.status != 200:
                continue

            # Check if this is actually a login page
            content = await page.content()
            if 'password' not in content.lower():
                continue

            await _fill_form_fields(page, identity)
            await _submit_form(page)
            await page.wait_for_timeout(3000)

            if await _check_logged_in(page):
                print(f"  [harvester] Login successful via {path}")
                return True

        except Exception:
            continue

    return False


async def _submit_deposit_form(page, base_url: str, output_dir: str, domain: str) -> dict:
    """
    Submit a deposit form to reveal the scam wallet address.
    Handles two patterns:
    1. Query param style: /?a=deposit
    2. Path style: /deposit
    Tries BTC first, then USDT, then ETH.
    """
    wallets = {}
    deposit_urls = [
        base_url + "/?a=deposit",
        base_url + "/deposit",
        base_url + "/user/deposit",
        base_url + "/dashboard/deposit",
    ]

    for deposit_url in deposit_urls:
        try:
            r = await page.goto(deposit_url, wait_until="domcontentloaded", timeout=15000)
            if not r or r.status in (404, 403, 500):
                continue

            await page.wait_for_timeout(1500)
            content = await page.content()

            # Check if this is actually a deposit page
            if not any(kw in content.lower() for kw in
                       ["deposit", "invest", "plan", "amount", "payment"]):
                continue

            # Select first available plan
            try:
                select = await page.query_selector("select")
                if select:
                    options = await select.query_selector_all("option")
                    # Pick first non-empty option
                    for opt in options:
                        val = await opt.get_attribute("value") or ""
                        if val and val != "0":
                            await select.select_option(val)
                            break
            except Exception:
                pass

            # Fill amount
            try:
                amt = await page.query_selector('input[name="amount"]')
                if amt:
                    await amt.fill("50")
            except Exception:
                pass

            # Try each payment type
            payment_values = [
                "process_1000",  # BTC
                "process_1001",  # USDT
                "process_1002",  # ETH
            ]

            for payment_val in payment_values:
                try:
                    radio = await page.query_selector(f'input[value="{payment_val}"]')
                    if not radio:
                        # Try generic radio buttons
                        radios = await page.query_selector_all('input[type="radio"]')
                        if radios:
                            radio = radios[0]
                    if radio:
                        await radio.click()
                        await page.wait_for_timeout(500)
                        break
                except Exception:
                    continue

            # Submit
            submitted = False
            for selector in ['button[type="submit"]', 'input[type="submit"]',
                             'button:has-text("Deposit")', 'button:has-text("Invest")',
                             'button:has-text("Continue")', 'button:has-text("Proceed")']:
                try:
                    btn = await page.query_selector(selector)
                    if btn and await btn.is_visible():
                        await btn.click()
                        submitted = True
                        break
                except Exception:
                    continue

            if not submitted:
                continue

            await page.wait_for_timeout(4000)

            # Extract wallet from reveal page
            content = await page.content()
            wallets = extract_wallets_from_text(content)

            # Check all input values including readonly fields
            inputs = await page.query_selector_all("input")
            for inp in inputs:
                val = await inp.get_attribute("value") or ""
                if val:
                    w = extract_wallets_from_text(val)
                    _merge_wallets(wallets, w)

            # Check data-clipboard-text attributes
            els = await page.query_selector_all("[data-clipboard-text]")
            for el in els:
                val = await el.get_attribute("data-clipboard-text") or ""
                if val:
                    w = extract_wallets_from_text(val)
                    _merge_wallets(wallets, w)

            if wallets:
                ss = f"{output_dir}/{domain.replace('.','_')}_deposit_reveal.png"
                await page.screenshot(path=ss, full_page=True)
                print(f"  [harvester] Wallet reveal screenshot: {ss}")
                return wallets

        except Exception:
            continue

    return wallets


async def harvest_wallets(domain: str, output_dir: str = "outputs") -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed", "wallets": {}}

    base_url  = f"https://{domain}"
    identity  = generate_fake_identity()
    Path(output_dir).mkdir(exist_ok=True)

    all_wallets          = {}
    screenshots          = []
    pages_visited        = []
    registration_success = False
    login_success        = False

    print(f"\n  [harvester] Starting headless browser for {domain}")
    print(f"  [harvester] Identity: {identity['email']} / {identity['password'][:4]}****")

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

        # ── Step 1: Homepage ──────────────────────────────────────────────────
        try:
            await page.goto(base_url, wait_until="networkidle", timeout=30000)
            content = await page.content()
            _merge_wallets(all_wallets, extract_wallets_from_text(content))
            pages_visited.append(base_url)
            ss = f"{output_dir}/{domain.replace('.','_')}_homepage.png"
            await page.screenshot(path=ss, full_page=True)
            screenshots.append(ss)
            print(f"  [harvester] Homepage loaded")

            # Check if already logged in (cached session)
            if await _check_logged_in(page):
                login_success = True
                print(f"  [harvester] Already authenticated")
        except Exception as e:
            print(f"  [harvester] Homepage failed: {e}")

        # ── Step 2: Register ──────────────────────────────────────────────────
        if not login_success:
            for path in REGISTER_PATHS:
                try:
                    r = await page.goto(base_url + path,
                                        wait_until="domcontentloaded", timeout=15000)
                    if not r or r.status != 200:
                        continue

                    content = await page.content()
                    if 'password' not in content.lower():
                        continue

                    print(f"  [harvester] Registering at {path}")
                    filled = await _fill_form_fields(page, identity)

                    if not filled:
                        continue

                    await _submit_form(page)
                    await page.wait_for_timeout(4000)

                    # Take screenshot to see what happened
                    ss = f"{output_dir}/{domain.replace('.','_')}_post_register.png"
                    await page.screenshot(path=ss, full_page=True)
                    screenshots.append(ss)
                    registration_success = True

                    # Check if we got logged in automatically after registration
                    if await _check_logged_in(page):
                        login_success = True
                        print(f"  [harvester] Auto-logged in after registration")
                        break

                    # Check for verification requirement
                    content = await page.content()
                    content_lower = content.lower()
                    if any(kw in content_lower for kw in
                           ["verify", "verification", "confirm your email", "activate"]):
                        print(f"  [harvester] Email verification required — trying direct login")
                        break

                    break
                except Exception:
                    continue

        # ── Step 3: Try login if not authenticated ────────────────────────────
        if not login_success:
            login_success = await _attempt_login(page, base_url, identity)
            if not login_success:
                print(f"  [harvester] Could not authenticate — scanning public pages only")

        # ── Step 4: Scan deposit pages (authenticated or not) ─────────────────
        print(f"  [harvester] Scanning {len(DEPOSIT_PATHS)} paths (authenticated={login_success})...")

        for path in DEPOSIT_PATHS:
            try:
                r = await page.goto(base_url + path,
                                    wait_until="domcontentloaded", timeout=15000)
                if not r or r.status in (404, 403, 500):
                    continue

                # Wait for dynamic content to load
                await page.wait_for_timeout(2500)

                # Also wait for any wallet address elements to appear
                try:
                    await page.wait_for_selector(
                        '[class*="wallet"], [class*="address"], [id*="wallet"], [id*="address"]',
                        timeout=3000
                    )
                except Exception:
                    pass

                content = await page.content()
                wallets = extract_wallets_from_text(content)

                # Also check for wallet addresses in input fields (copy-to-clipboard pattern)
                try:
                    inputs = await page.query_selector_all(
                        'input[readonly], input[disabled], input[class*="wallet"], input[class*="address"]'
                    )
                    for inp in inputs:
                        val = await inp.get_attribute("value") or ""
                        if val:
                            w = extract_wallets_from_text(val)
                            _merge_wallets(wallets, w)
                except Exception:
                    pass

                if wallets:
                    _merge_wallets(all_wallets, wallets)
                    pages_visited.append(base_url + path)
                    print(f"  [harvester] WALLETS on {path}: {wallets}")
                    ss = f"{output_dir}/{domain.replace('.','_')}{path.replace('/','_')}.png"
                    await page.screenshot(path=ss, full_page=True)
                    screenshots.append(ss)

                # QR codes
                qr = await page.query_selector_all(
                    "img[src*='qr' i], img[alt*='qr' i], canvas[class*='qr' i]"
                )
                if qr:
                    print(f"  [harvester] QR code detected on {path}")
                    ss = f"{output_dir}/{domain.replace('.','_')}{path.replace('/','_')}_qr.png"
                    await page.screenshot(path=ss, full_page=True)
                    screenshots.append(ss)

            except Exception:
                continue

        # ── Step 5: Submit deposit form to reveal wallet address ──────────────
        if login_success and not all_wallets:
            print(f"  [harvester] Trying deposit form submission to reveal wallet...")
            try:
                wallets = await _submit_deposit_form(page, base_url, output_dir, domain)
                if wallets:
                    _merge_wallets(all_wallets, wallets)
                    print(f"  [harvester] WALLETS via deposit form: {wallets}")
            except Exception as e:
                print(f"  [harvester] Deposit form submission failed: {e}")

        await browser.close()

    total = sum(len(v) for v in all_wallets.values())
    print(f"  [harvester] Done — {total} wallets, logged_in={login_success}")

    # Blockchain analysis
    blockchain_results = {}
    total_usd = 0.0
    if all_wallets:
        print(f"  [harvester] Analyzing on blockchain...")
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
                        print(f"  [harvester] {currency} {addr[:16]}... → ${usd:,.2f}")
        except Exception as e:
            print(f"  [harvester] Blockchain error: {e}")

    if total_usd > 0:
        print(f"  [harvester] TOTAL VICTIM LOSSES: ${total_usd:,.2f}")

    return {
        "wallets":                all_wallets,
        "wallet_count":           total,
        "blockchain":             blockchain_results,
        "total_usd":              total_usd,
        "pages_visited":          pages_visited,
        "screenshots":            screenshots,
        "registration_attempted": registration_success,
        "login_success":          login_success,
        "fake_email":             identity["email"],
        "timestamp":              datetime.now().isoformat(),
    }


def harvest_wallets_sync(domain: str, output_dir: str = "outputs") -> dict:
    return asyncio.run(harvest_wallets(domain, output_dir))


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "stake2earn.app"
    result = harvest_wallets_sync(domain)
    print(json.dumps(result, indent=2, default=str))
