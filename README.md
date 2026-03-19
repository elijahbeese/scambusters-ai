<div align="center">

```
███████╗ ██████╗ █████╗ ███╗   ███╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗████╗ ████║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝
███████╗██║     ███████║██╔████╔██║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝███████╗
╚════██║██║     ██╔══██║██║╚██╔╝██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗╚════██║
███████║╚██████╗██║  ██║██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║███████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
                                        A G E N T
```

**AI-powered crypto scam investigation. Automated OSINT. Blockchain tracing. Federal-grade reporting.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![OpenAI](https://img.shields.io/badge/GPT--4o-powered-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-production-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Railway](https://img.shields.io/badge/Deployed-Railway-0B0D0E?style=flat-square&logo=railway&logoColor=white)](https://railway.app)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

*Built for the University of Tampa Center for Cybersecurity — Intelligence For Good ScamBusters® Program*

*UTampa Cyber Spartans · I4G ScamBusters University Edition*

</div>

---

## What is this?

Crypto investment scams (HYIPs) steal billions annually. The FBI IC3 report shows investment fraud surpassed Business Email Compromise in 2022 and hasn't slowed down. The FTC reported $5.7 billion in total fraud losses in 2024, with investment scams accounting for nearly half.

**ScamBusters Agent** automates the full investigation pipeline used by Intelligence For Good — from discovering active scam sites, mapping their infrastructure, tracing victim funds on the blockchain, attributing threat actors, and generating federal-grade referral packages — so investigators can move faster than the scammers do.

---

## What it does in a single run

```
🔍  Discovers active crypto scam domains from 15 HYIP monitoring sites + threat intel feeds
🌐  URLScan — IP, ASN, hosting info, visually similar sites (template cluster mapping)
📋  WHOIS — registrar, creation date, abuse contacts, SOA email (threat actor pivot)
🗄️  Passive DNS — historical IPs, linked domains, SOA cluster (operator attribution)
🤖  Playwright Harvester v21:
        → GPT-4o Vision solves image captchas automatically
        → Registers fake account using mail.tm API (real inbox, auto email verification)
        → Universal form scanner fills ANY site's fields without hardcoded selectors
        → Submits deposit form to reveal hidden wallet addresses
        → Extracts wallets from page text, input values, clipboard attributes
🔐  Certificate transparency — subdomains via crt.sh
🛡️  VirusTotal — malicious/suspicious vendor verdicts
🔌  Shodan — open ports, exposed admin panels, server banners
💰  Blockchain — BTC/ETH/USDT wallet tracing (blockchain.info → mempool.space → Blockchair)
🕸️  IP Cluster Auto-Investigation — top scam-scored domains on same IP investigated automatically
🧠  GPT-4o — structured intelligence report with operator attribution
📊  Risk scoring — weighted 0-100 score (MINIMAL / LOW / MEDIUM / HIGH / CRITICAL)
📨  Takedown emails — registrar + hosting provider abuse contacts
🏛️  Law enforcement package — IC3-formatted narrative + evidence bundle
```

---

## Live Example

```bash
python3 agent.py assetinvestbrokers.com
```

```
[urlscan]    IP: 188.114.96.3 | Cloudflare | 9 visual clones
[whois]      Registrar: Ultahost | Abuse: u-abuse@ultahost.com
[passive_dns] 208 domains on same IP
[social]     Telegram: @EmilyIsabella @EmilyIsabella2
[harvester]  GPT-4o solved captcha → registered → verified email → logged in
[harvester]  Submitted deposit form → BTC: bc1qgl5daf3mgjscpx68rdpxtceslql5cgvvt9nz88
[blockchain] $1,688.66 traced | 19 transactions | active Jun 2025
[risk]       MEDIUM (41/100) — $1,689 on-chain · Telegram · 3 AV flags
[done]       IC3 package + takedown emails → outputs/
```

---

## Pipeline

```
15 HYIP Monitors + URLScan + PhishTank + OpenPhish + Telegram
                            │
                    Discord Bounty Intake
                            │
         URLScan ──► WHOIS ──► Passive DNS ──► Social OSINT
                            │
              ┌─────────────▼─────────────┐
              │   Playwright Harvester v21  │
              │  • GPT-4o Vision captchas   │
              │  • mail.tm email verify     │
              │  • Universal form scanner   │
              │  • Deposit form submission  │
              └─────────────┬─────────────┘
                            │
              IP Cluster Auto-Investigation
              (top 3 scam domains on same IP)
                            │
              crt.sh + VirusTotal + Shodan
                            │
         Blockchain Analysis (BTC/ETH/USDT/SOL/LTC/DOGE)
                            │
              GPT-4o Intelligence Report
                            │
                   Risk Score (0-100)
                            │
              Takedown Emails + IC3 Package
```

---

## Wallet Harvester v21

The most advanced component. Extracts cryptocurrency wallet addresses from behind authentication on any HYIP site.

**How it works:**
1. Creates a real `mail.tm` inbox via API (not blocked by scam sites)
2. Uses GPT-4o Vision to solve image captchas automatically
3. Scans every visible input field and fills them intelligently — works on ANY field naming convention
4. Registers, handles email verification automatically by polling the mail.tm API
5. Logs in with verified credentials
6. Navigates to deposit pages and extracts wallet addresses
7. Submits deposit forms to reveal wallet addresses only shown after payment selection
8. Extracts from page text, readonly input values, data-clipboard attributes, QR code screenshots

---

## Autonomous Mode

No bounty needed. Finds and investigates scams automatically 24/7.

**Discovery Sources (15 total):**

| Source | Type |
|--------|------|
| tophyip.biz | I4G HYIP Monitor |
| payinghyiponline.com | I4G HYIP Monitor |
| invest-tracing.com | I4G HYIP Monitor |
| bestemoneys.com | I4G HYIP Monitor |
| phyip.com | I4G HYIP Monitor |
| hyip.biz | I4G HYIP Monitor |
| sqmonitor.com | I4G HYIP Monitor |
| hyipbanker.com | I4G HYIP Monitor |
| hothyips.com | I4G HYIP Monitor |
| hyipmonitors24.net | I4G HYIP Monitor |
| URLScan cryptoscam tag | Community-verified |
| CryptoScamDB | Crypto fraud DB |
| OpenPhish | Phishing feed |
| PhishTank | Crowdsourced phishing |
| Telegram channels | Scam promotion monitoring |

```bash
python3 autonomous.py --discover              # See what's out there
python3 autonomous.py --count 10             # Investigate top 10
python3 autonomous.py --continuous --count 20 --interval 4  # Run forever
```

---

## Stack

| Layer | Tech |
|-------|------|
| Language | Python 3.10+ |
| AI | OpenAI GPT-4o + GPT-4o Vision |
| Browser Automation | Playwright (Chromium) |
| Email Verification | mail.tm REST API |
| Captcha Solving | GPT-4o Vision (no external service) |
| Web | Flask + Gunicorn |
| Database | PostgreSQL |
| Deployment | Railway |
| Blockchain (BTC) | blockchain.info → mempool.space → Blockchair |
| Blockchain (ETH) | Etherscan V2 API |
| Blockchain (USDT) | TronScan → Blockchair TRON |
| Visualization | D3.js network graph |

---

## API Keys

| Variable | Required | Source |
|----------|----------|--------|
| `OPENAI_API_KEY` | ✅ | [platform.openai.com](https://platform.openai.com) — also powers GPT-4o Vision captcha solver |
| `URLSCAN_API_KEY` | ✅ | [urlscan.io](https://urlscan.io) |
| `VIRUSTOTAL_API_KEY` | ✅ | [virustotal.com](https://virustotal.com) |
| `SHODAN_API_KEY` | ✅ | [shodan.io](https://shodan.io) |
| `ETHERSCAN_API_KEY` | ✅ | [etherscan.io/apis](https://etherscan.io/apis) |
| `ZETALYTICS_API_KEY` | ⬜ | [zonecruncher.com](https://zonecruncher.com) |

---

## Setup

```bash
git clone https://github.com/elijahbeese/scambusters-agent
cd scambusters-agent
git checkout v2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
cp .env_example .env
# Add API keys to .env
createdb scambusters
python3 -c "from scripts.db import init_db; init_db()"
python3 app.py  # → http://localhost:5000
```

---

## Changelog

### v21 (March 2026) — Current
- **mail.tm integration** — real REST API inbox, email verification fully automated
- **GPT-4o Vision captcha solver** — downloads captcha image, sends to GPT-4o, fills solution automatically
- **Universal form scanner** — scans every visible input field dynamically, no hardcoded selectors
- **IP cluster auto-investigation** — top 3 scam-scored domains on same IP investigated automatically
- **BTC regex fix** — proper base58 charset, rejects MD5 hashes and hex strings
- **SOL false positive fix** — requires non-hex chars, eliminates encoded garbage
- **login detection fix** — requires actual logout link, eliminates false positives

### v20 (March 2026)
- Rewrote wallet harvester from scratch with adaptive field detection
- GPT-4o form analysis strategy generation
- Deposit form submission to reveal hidden wallet addresses
- Autonomous discovery engine with 15 sources

### v2.0 (March 2026)
- Playwright wallet harvester — registers fake accounts, navigates deposit pages
- Autonomous discovery engine
- BTC blockchain.info primary, mempool.space + Blockchair fallback
- ETH Etherscan V2 API
- PostgreSQL migration
- Railway deployment
- Public dashboard with I4G leaderboard widget

### v1.0 (Initial)
- 7-stage pipeline: URLScan → WHOIS → Passive DNS → Social OSINT → crt.sh/VT/Shodan → GPT-4o → Takedowns
- SQLite, Flask dashboard, basic wallet extraction

---

## OpSec

> ⚠️ Always investigate behind a VPN.
> Never enter real personal information on scam sites.
> Run in a sandboxed environment when possible.

---

## Based on

ScamBusters® curriculum — University of Tampa Center for Cybersecurity
Methodology by [Intelligence For Good](https://intelligenceforgood.org) and UAB Cyber Forensics Research Laboratory

Built by **Elijah Beese** · University of Tampa · Army ROTC Cadet

---

<div align="center">

[![I4G Leaderboard](https://img.shields.io/badge/I4G-ScamBusters%20University-00d4aa?style=flat-square)](https://www.intelligenceforgood.org/scambusters-leaderboard)
[![UTampa Cyber Spartans](https://img.shields.io/badge/Team-UTampa%20Cyber%20Spartans-0099ff?style=flat-square)](https://www.intelligenceforgood.org/scambusters-leaderboard)

*Fighting scams, one takedown at a time.*

</div>
