"""
wallet_harvester.py v21 — GPT-4o Vision Captcha + Email Verification + Universal Form Engine
"""

import os
import re
import sys
import json
import base64
import random
import string
import asyncio
import requests
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")


import imaplib
import email as email_lib
from email.header import decode_header

GMAIL_ADDRESS  = os.getenv("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")


def _get_gmail_verification_link(timeout: int = 90) -> str | None:
    """Poll Gmail inbox via IMAP for verification link."""
    import time
    start = time.time()
    while time.time() - start < timeout:
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            mail.select("inbox")
            _, msgs = mail.search(None, "UNSEEN")
            for num in reversed(msgs[0].split()):
                _, data = mail.fetch(num, "(RFC822)")
                msg = email_lib.message_from_bytes(data[0][1])
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/html":
                            body += part.get_payload(decode=True).decode(errors="ignore")
                else:
                    body = msg.get_payload(decode=True).decode(errors="ignore")
                pattern = r"https?://[^\s\"'<>]+(?:verif|confirm|activ|token|valid)[^\s\"'<>]+"
                urls = re.findall(pattern, body)
                if urls:
                    mail.logout()
                    return urls[0].rstrip('"').rstrip("'")
            mail.logout()
        except Exception as e:
            print(f"  [harvester] Gmail IMAP error: {e}")
        time.sleep(8)
    return None

WALLET_PATTERNS = {
    "BTC":        r"\b(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
    "ETH":        r"\b(0x[a-fA-F0-9]{40})\b",
    "USDT_TRC20": r"\b(T[A-Za-z0-9]{33})\b",
    "LTC":        r"\b(ltc1[a-zA-Z0-9]{25,62}|[LM][a-zA-Z0-9]{26,33})\b",
    "XRP":        r"\b(r[0-9a-zA-Z]{24,34})\b",
    "DOGE":       r"\b(D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{24,33})\b",
    "SOL":        r"\b([1-9A-HJ-NP-Za-km-z]{43,44})\b",
    "BNB":        r"\b(bnb1[a-zA-Z0-9]{38})\b",
}

FALSE_POSITIVE_CHECKS = {
    "SOL": lambda addr: bool(re.search(r'[g-zG-Z]', addr)),
    "BTC": lambda addr: not bool(re.match(r'^[0-9a-f]{32,}$', addr)),
    "LTC": lambda addr: not addr.isalpha(),
    "XRP": lambda addr: any(c.isdigit() for c in addr),
}

DEPOSIT_PATHS = [
    "/deposit", "/invest", "/payment", "/fund", "/plans", "/packages",
    "/user/deposit", "/user/invest", "/dashboard/deposit", "/dashboard/invest",
    "/account/deposit", "/wallet/deposit", "/member/deposit",
    "/crypto/deposit", "/fund/deposit", "/invest/plans",
    "/?a=deposit", "/?a=invest", "/?a=payment", "/?a=wallet",
    "/?a=dashboard", "/?a=fund", "/?a=plans",
    "/?page=deposit", "/?page=invest",
]

REGISTER_PATHS = [
    "/register", "/signup", "/sign-up", "/join", "/create-account",
    "/user/register", "/account/register", "/auth/register",
    "/en/register", "/app/register", "/member/register",
    "/?a=signup", "/?a=register", "/?a=join", "/?page=register",
]

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/user/login", "/account/login",
    "/auth/login", "/en/login", "/app/login", "/member/login",
    "/?a=login", "/?a=signin", "/?page=login",
]


def generate_fake_identity() -> dict:
    first_names = ["James", "Michael", "Robert", "David", "John",
                   "Sarah", "Emma", "Lisa", "Anna", "Maria"]
    last_names  = ["Smith", "Johnson", "Williams", "Brown", "Jones",
                   "Garcia", "Miller", "Davis", "Wilson", "Taylor"]
    first    = random.choice(first_names)
    last     = random.choice(last_names)
    username = f"{first.lower()}{last.lower()}{random.randint(1000, 9999)}"
    # Get mail.tm domain dynamically
    try:
        _r = requests.get("https://api.mail.tm/domains", timeout=5)
        _domain = _r.json()["hydra:member"][0]["domain"] if _r.status_code == 200 else "sharebot.net"
    except Exception:
        _domain = "sharebot.net"
    email    = GMAIL_ADDRESS if GMAIL_ADDRESS else f"{username}@{_domain}"
    chars    = string.ascii_letters + string.digits
    password = "".join(random.choices(chars, k=10)) + "1Aa!"
    return {
        "first_name":  first,
        "last_name":   last,
        "full_name":   f"{first} {last}",
        "username":    username,
        "email":       email,
        "password":    password,
        "phone":       f"+1{random.randint(2000000000, 9999999999)}",
        "btc_wallet":  "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf6a",
        "eth_wallet":  "0x0000000000000000000000000000000000000001",
        "usdt_wallet": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "ltc_wallet":  "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",
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
            check = FALSE_POSITIVE_CHECKS.get(currency)
            if check and not check(addr):
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


def _create_mailtm_account(email: str, password: str) -> str | None:
    """Create a mail.tm account and return auth token."""
    try:
        r = requests.post("https://api.mail.tm/accounts",
            json={"address": email, "password": password},
            headers={"Content-Type": "application/json"}, timeout=10)
        if r.status_code not in (201, 422):  # 422 = already exists
            return None
        r2 = requests.post("https://api.mail.tm/token",
            json={"address": email, "password": password},
            headers={"Content-Type": "application/json"}, timeout=10)
        if r2.status_code == 200:
            return r2.json().get("token")
    except Exception:
        pass
    return None


def _get_mailtm_verification_link(token: str, timeout: int = 90) -> str | None:
    """Poll mail.tm inbox for verification link."""
    import time
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get("https://api.mail.tm/messages",
                headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if r.status_code == 200:
                messages = r.json().get("hydra:member", [])
                for msg in messages:
                    msg_id = msg.get("id")
                    r2 = requests.get(f"https://api.mail.tm/messages/{msg_id}",
                        headers={"Authorization": f"Bearer {token}"}, timeout=10)
                    if r2.status_code == 200:
                        body = r2.json().get("text", "") + r2.json().get("html", "")
                        pattern = r'https?://[^\s"\'<>]+(?:verif|confirm|activ|token|valid)[^\s"\'<>]+'
                        urls = re.findall(pattern, body)
                        if urls:
                            return urls[0].rstrip('"').rstrip("'")
        except Exception:
            pass
        time.sleep(8)
    return None


async def _extract_wallets_from_page(page) -> dict:
    wallets = {}
    try:
        content = await page.content()
        _merge_wallets(wallets, extract_wallets_from_text(content))
    except Exception:
        pass
    try:
        inputs = await page.query_selector_all("input, textarea")
        for inp in inputs:
            val = await inp.get_attribute("value") or ""
            if val and len(val) > 20:
                _merge_wallets(wallets, extract_wallets_from_text(val))
    except Exception:
        pass
    try:
        els = await page.query_selector_all("[data-clipboard-text], [data-copy], [data-value]")
        for el in els:
            for attr in ["data-clipboard-text", "data-copy", "data-value"]:
                val = await el.get_attribute(attr) or ""
                if val:
                    _merge_wallets(wallets, extract_wallets_from_text(val))
    except Exception:
        pass
    return wallets


async def _solve_captcha_with_vision(page, base_url: str) -> str | None:
    if not OPENAI_API_KEY:
        return None
    try:
        captcha_img = await page.query_selector(
            "img.captcha-image, img[alt*='captcha' i], img[src*='captcha' i], "
            "img[src*='secure' i], img[id*='captcha' i], img[class*='captcha' i]"
        )
        if not captcha_img:
            return None
        captcha_src = await captcha_img.get_attribute("src")
        if not captcha_src:
            return None
        if captcha_src.startswith("/"):
            captcha_src = base_url + captcha_src
        elif not captcha_src.startswith("http"):
            captcha_src = base_url + "/" + captcha_src
        r = requests.get(captcha_src, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return None
        img_b64 = base64.b64encode(r.content).decode()
        content_type = r.headers.get("content-type", "image/png").split(";")[0]
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}",
                     "Content-Type": "application/json"},
            json={
                "model": "gpt-4o",
                "max_tokens": 20,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "image_url",
                         "image_url": {"url": f"data:{content_type};base64,{img_b64}", "detail": "high"}},
                        {"type": "text",
                         "text": "This is a CAPTCHA. Return ONLY the characters shown, nothing else."}
                    ]
                }]
            },
            timeout=30
        )
        if response.status_code == 200:
            answer = response.json()["choices"][0]["message"]["content"].strip()
            answer = re.sub(r'[\s"\'`]', '', answer)
            print(f"  [harvester] GPT-4o captcha: '{answer}'")
            return answer
    except Exception as e:
        print(f"  [harvester] Captcha error: {e}")
    return None


async def _scan_and_fill_form(page, identity: dict) -> int:
    try:
        inputs = await page.query_selector_all(
            "input:not([type='hidden']):not([type='submit']):not([type='button']):not([type='image']), "
            "select, textarea"
        )
    except Exception:
        return 0

    filled = 0
    for inp in inputs:
        try:
            if not await inp.is_visible():
                continue
            readonly = await inp.get_attribute("readonly")
            if readonly is not None:
                continue

            name        = (await inp.get_attribute("name") or "").lower()
            placeholder = (await inp.get_attribute("placeholder") or "").lower()
            itype       = (await inp.get_attribute("type") or "text").lower()
            id_attr     = (await inp.get_attribute("id") or "").lower()
            combined    = f"{name} {placeholder} {id_attr}"
            value       = None

            if itype == "password":
                value = identity["password"]
            elif itype == "email" or "email" in combined:
                value = identity["email"]
            elif name in ("user_name", "fullname", "full_name") or \
                 (placeholder in ("full name", "your name", "fullname")):
                value = identity["full_name"]
            elif name in ("user_username", "username", "user_login") and \
                 not any(kw in name for kw in ["upline", "refer", "sponsor"]):
                value = identity["username"]
            elif any(kw in combined for kw in ["first_name", "firstname", "fname"]):
                value = identity["first_name"]
            elif any(kw in combined for kw in ["last_name", "lastname", "lname", "surname"]):
                value = identity["last_name"]
            elif itype == "tel" or any(kw in combined for kw in ["phone", "mobile"]):
                value = identity["phone"]
            elif any(kw in name for kw in ["wallet_btc", "btcwallet"]) or "bitcoin" in placeholder:
                value = identity["btc_wallet"]
            elif any(kw in name for kw in ["wallet_bch"]) or "bitcoincash" in placeholder:
                value = identity["btc_wallet"]
            elif any(kw in name for kw in ["wallet_usdt"]) or any(kw in placeholder for kw in ["usdt", "trc20"]):
                value = identity["usdt_wallet"]
            elif any(kw in name for kw in ["wallet_eth"]) or "ethereum" in placeholder:
                value = identity["eth_wallet"]
            elif any(kw in name for kw in ["wallet_ltc"]) or "litecoin" in placeholder:
                value = identity["ltc_wallet"]
            elif "wallet" in name and "address" in placeholder:
                value = identity["btc_wallet"]
            elif name == "amount" or "amount" in placeholder:
                value = "50"
            elif any(kw in name for kw in ["upline", "referral", "ref", "sponsor"]):
                value = ""
            elif any(kw in name for kw in ["botcheck", "botCheck", "captcha"]) and itype == "text":
                value = str(random.randint(1000, 9999))

            if value is not None:
                tag = await inp.evaluate("el => el.tagName.toLowerCase()")
                if tag == "select":
                    options = await inp.query_selector_all("option")
                    for opt in options:
                        opt_val = await opt.get_attribute("value") or ""
                        if opt_val and opt_val not in ("0", "", "select", "none"):
                            await inp.select_option(opt_val)
                            filled += 1
                            break
                else:
                    await inp.fill(str(value))
                    filled += 1
        except Exception:
            continue

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
    selectors = [
        'button[type="submit"]', 'input[type="submit"]',
        'button:has-text("Register")', 'button:has-text("Sign Up")',
        'button:has-text("Create Account")', 'button:has-text("Join")',
        'button:has-text("Login")', 'button:has-text("Sign In")',
        'button:has-text("Submit")', 'button:has-text("Continue")',
        'button:has-text("Make Deposit")', 'button:has-text("Deposit")',
        'button:has-text("Invest")', '.btn-primary', '.thm-btn',
        '.submit-btn', '#submit', 'button[class*="submit"]',
        'button[class*="register"]', 'button[class*="login"]',
    ]
    for sel in selectors:
        try:
            btn = await page.query_selector(sel)
            if btn and await btn.is_visible():
                await btn.click()
                await page.wait_for_timeout(3000)
                return True
        except Exception:
            continue
    return False


async def _check_logged_in(page) -> bool:
    try:
        content = await page.content()
        content_lower = content.lower()
        url = page.url.lower()
        has_logout = any(kw in content_lower for kw in ["logout", "log out", "sign out", "signout"])
        if not has_logout:
            return False
        if any(kw in url for kw in ["dashboard", "account", "member", "portal"]):
            return True
        signals = ["deposit", "withdraw", "balance", "investment", "portfolio", "my account"]
        return sum(1 for kw in signals if kw in content_lower) >= 2
    except Exception:
        return False


async def _attempt_registration(page, base_url: str, identity: dict) -> bool:
    for path in REGISTER_PATHS:
        try:
            r = await page.goto(base_url + path, wait_until="domcontentloaded", timeout=15000)
            if not r or r.status in (404, 403, 500):
                continue
            content = await page.content()
            if "password" not in content.lower():
                continue

            filled = await _scan_and_fill_form(page, identity)
            if not filled:
                continue

            captcha_answer = await _solve_captcha_with_vision(page, base_url)
            if captcha_answer:
                for captcha_sel in ['input[name="botCheck"]', 'input[name="captcha"]',
                                    'input[id="captcha"]', 'input[class*="captcha"]']:
                    try:
                        el = await page.query_selector(captcha_sel)
                        if el and await el.is_visible():
                            await el.fill(captcha_answer)
                            break
                    except Exception:
                        continue

            await _submit_form(page)
            await page.wait_for_timeout(3000)

            post_url = page.url
            has_error = "itts" in post_url.lower() or "/error" in post_url.lower()
            print(f"  [harvester] Registration at {path} → {post_url} error={has_error}")

            if has_error:
                continue
            
            # Save credentials so we can reuse this account
            import json as _json
            creds_file = "outputs/registered_accounts.json"
            try:
                creds = _json.load(open(creds_file)) if os.path.exists(creds_file) else {}
            except Exception:
                creds = {}
            creds[base_url] = {"email": identity["email"], "username": identity["username"], "password": identity["password"]}
            _json.dump(creds, open(creds_file, "w"), indent=2)

            if await _check_logged_in(page):
                print(f"  [harvester] Auto-logged in after registration")
                return True

            # Check for email verification requirement
            post_content = await page.content()
            needs_verify = any(kw in post_content.lower() for kw in
                               ["verify your email", "verification", "confirm your email",
                                "check your email", "activate your account", "validate"])
            if needs_verify:
                print(f"  [harvester] Email verification required — checking Gmail...")
                verify_url = _get_gmail_verification_link(timeout=90) if GMAIL_ADDRESS else None
                if verify_url:
                    print(f"  [harvester] Clicking verification link...")
                    await page.goto(verify_url, wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(2000)
                    print(f"  [harvester] After verification: {page.url}")
                else:
                    print(f"  [harvester] No verification email received")

            return True
        except Exception:
            continue
    return False


async def _attempt_login(page, base_url: str, identity: dict) -> bool:
    for path in LOGIN_PATHS:
        try:
            r = await page.goto(base_url + path, wait_until="domcontentloaded", timeout=15000)
            if not r or r.status in (404, 403, 500):
                continue
            content = await page.content()
            if "password" not in content.lower():
                continue

            filled = await _scan_and_fill_form(page, identity)
            if not filled:
                continue

            captcha_answer = await _solve_captcha_with_vision(page, base_url)
            if captcha_answer:
                for captcha_sel in ['input[name="botCheck"]', 'input[name="captcha"]',
                                    'input[id="captcha"]']:
                    try:
                        el = await page.query_selector(captcha_sel)
                        if el and await el.is_visible():
                            await el.fill(captcha_answer)
                            break
                    except Exception:
                        continue

            await _submit_form(page)
            await page.wait_for_timeout(3000)

            post_url = page.url
            print(f"  [harvester] Login via {path} → {post_url}")
            if await _check_logged_in(page):
                print(f"  [harvester] Login successful!")
                return True
        except Exception as e:
            continue
    return False


async def _submit_deposit_form(page, base_url: str, output_dir: str, domain: str) -> dict:
    wallets = {}
    for path in DEPOSIT_PATHS:
        try:
            r = await page.goto(base_url + path, wait_until="domcontentloaded", timeout=15000)
            if not r or r.status in (404, 403, 500):
                continue
            await page.wait_for_timeout(2000)
            content = await page.content()
            if not any(kw in content.lower() for kw in
                       ["deposit", "invest", "plan", "amount", "payment", "bitcoin", "wallet"]):
                continue

            try:
                selects = await page.query_selector_all("select")
                for sel in selects:
                    options = await sel.query_selector_all("option")
                    for opt in options:
                        val = await opt.get_attribute("value") or ""
                        if val and val not in ("0", "", "select", "none"):
                            await sel.select_option(val)
                            break
            except Exception:
                pass

            try:
                for amt_sel in ['input[name="amount"]', 'input[placeholder*="amount" i]']:
                    amt = await page.query_selector(amt_sel)
                    if amt and await amt.is_visible():
                        await amt.fill("50")
                        break
            except Exception:
                pass

            payment_clicked = False
            for val in ["process_1000", "btc", "bitcoin", "1", "crypto"]:
                try:
                    radio = await page.query_selector(f'input[value="{val}"]')
                    if radio:
                        await radio.click()
                        payment_clicked = True
                        break
                except Exception:
                    pass

            if not payment_clicked:
                try:
                    radios = await page.query_selector_all('input[type="radio"]')
                    if radios:
                        await radios[0].click()
                except Exception:
                    pass

            await _submit_form(page)
            await page.wait_for_timeout(4000)

            wallets = await _extract_wallets_from_page(page)
            if wallets:
                ss = f"{output_dir}/{domain.replace('.','_')}_deposit_reveal.png"
                await page.screenshot(path=ss, full_page=True)
                print(f"  [harvester] Deposit reveal → {wallets}")
                return wallets
        except Exception:
            continue
    return wallets


async def harvest_wallets(domain: str, output_dir: str = "outputs") -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed", "wallets": {}}

    base_url = f"https://{domain}"
    identity = generate_fake_identity()
    Path(output_dir).mkdir(exist_ok=True)

    all_wallets          = {}
    screenshots          = []
    pages_visited        = []
    registration_success = False
    login_success        = False

    print(f"\n  [harvester] v21 — {domain}")
    print(f"  [harvester] Identity: {identity['email']}")
    print(f"  [harvester] GPT-4o Vision: {'ENABLED' if OPENAI_API_KEY else 'DISABLED'}")

    # Check for existing credentials
    saved_creds = {}
    try:
        import json as _json
        creds_file = "outputs/registered_accounts.json"
        if os.path.exists(creds_file):
            all_creds = _json.load(open(creds_file))
            saved_creds = all_creds.get(f"https://{domain}", {})
            if saved_creds:
                print(f"  [harvester] Found saved credentials for {domain}")
                identity.update(saved_creds)
    except Exception:
        pass

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

        # Phase 1: Homepage
        try:
            await page.goto(base_url, wait_until="networkidle", timeout=30000)
            wallets = await _extract_wallets_from_page(page)
            _merge_wallets(all_wallets, wallets)
            pages_visited.append(base_url)
            ss = f"{output_dir}/{domain.replace('.','_')}_homepage.png"
            await page.screenshot(path=ss, full_page=True)
            screenshots.append(ss)
            print(f"  [harvester] Homepage loaded")
            if await _check_logged_in(page):
                login_success = True
        except Exception as e:
            print(f"  [harvester] Homepage failed: {e}")

        # Phase 2: Register
        if not login_success:
            registration_success = await _attempt_registration(page, base_url, identity)
            if registration_success:
                ss = f"{output_dir}/{domain.replace('.','_')}_post_register.png"
                await page.screenshot(path=ss, full_page=True)
                screenshots.append(ss)
                if await _check_logged_in(page):
                    login_success = True
                else:
                    login_success = await _attempt_login(page, base_url, identity)

        # Phase 3: Login if needed
        if not login_success:
            login_success = await _attempt_login(page, base_url, identity)
            if not login_success:
                print(f"  [harvester] Could not authenticate — public scan only")

        # Phase 4: Scan deposit paths
        print(f"  [harvester] Scanning paths (auth={login_success})...")
        for path in DEPOSIT_PATHS:
            try:
                r = await page.goto(base_url + path, wait_until="domcontentloaded", timeout=15000)
                if not r or r.status in (404, 403, 500):
                    continue
                await page.wait_for_timeout(2000)
                wallets = await _extract_wallets_from_page(page)
                if wallets:
                    _merge_wallets(all_wallets, wallets)
                    pages_visited.append(base_url + path)
                    print(f"  [harvester] WALLETS on {path}: {wallets}")
                    ss = f"{output_dir}/{domain.replace('.','_')}{path.replace('/','_').replace('?','_').replace('=','_')}.png"
                    await page.screenshot(path=ss, full_page=True)
                    screenshots.append(ss)
                try:
                    qr = await page.query_selector_all("img[src*='qr' i], canvas[class*='qr' i]")
                    if qr:
                        ss = f"{output_dir}/{domain.replace('.','_')}{path.replace('/','_')}_qr.png"
                        await page.screenshot(path=ss, full_page=True)
                        screenshots.append(ss)
                        print(f"  [harvester] QR on {path}")
                except Exception:
                    pass
            except Exception:
                continue

        # Phase 5: Deposit form submission
        if login_success and not all_wallets:
            print(f"  [harvester] Submitting deposit form...")
            try:
                deposit_wallets = await _submit_deposit_form(page, base_url, output_dir, domain)
                if deposit_wallets:
                    _merge_wallets(all_wallets, deposit_wallets)
            except Exception as e:
                print(f"  [harvester] Deposit form error: {e}")

        await browser.close()

    total = sum(len(v) for v in all_wallets.values())
    print(f"  [harvester] Done — {total} wallets, auth={login_success}")

    # Phase 6: Blockchain
    blockchain_results = {}
    total_usd = 0.0
    if all_wallets:
        print(f"  [harvester] Tracing on blockchain...")
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
        print(f"  [harvester] TOTAL: ${total_usd:,.2f}")

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
    domain = sys.argv[1] if len(sys.argv) > 1 else "vevrecapital.net"
    result = harvest_wallets_sync(domain)
    print(json.dumps(result, indent=2, default=str))
