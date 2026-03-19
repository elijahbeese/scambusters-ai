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
🔍  Discovers active crypto scam domains from HYIP monitoring sites + URLScan tag feed
🌐  URLScan — IP, ASN, hosting info, visually similar sites (template cluster mapping)
📋  WHOIS — registrar, creation date, abuse contacts, SOA email (threat actor pivot)
🗄️  Passive DNS — historical IPs, linked domains, SOA cluster (operator attribution)
🔐  Certificate transparency — subdomains via crt.sh
🛡️  VirusTotal — malicious/suspicious vendor verdicts
🔌  Shodan — open ports, exposed admin panels, server banners
🤖  Playwright Harvester — headless Chrome registers fake account, logs in, submits
        deposit form, extracts real wallet addresses from behind authentication
💰  Blockchain analysis — BTC/ETH/USDT wallet transaction history, USD traced on-chain
📡  Social OSINT — Telegram channels, WhatsApp groups, Google Dork queries
🧠  GPT-4o — structured intelligence report with operator attribution
📊  Risk scoring — weighted 0-100 score (MINIMAL / LOW / MEDIUM / HIGH / CRITICAL)
📨  Takedown emails — registrar + hosting provider abuse contacts
🏛️  Law enforcement package — IC3-formatted narrative + evidence bundle
🕸️  Network graph — D3.js force graph connecting domains, IPs, wallets, operators
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
[harvester]  Registered fake account → logged in → submitted deposit form
[harvester]  BTC: bc1qgl5daf3mgjscpx68rdpxtceslql5cgvvt9nz88
[blockchain] $1,688.66 traced | 19 transactions | active Jun 2025
[risk]       MEDIUM (41/100) — $1,689 on-chain · Telegram · 3 AV flags
[done]       IC3 package + takedown emails → outputs/
```

---

## Pipeline

```
HYIP Monitors + URLScan Tag ──► Discord Bounty Intake
                                        │
                                        ▼
         URLScan ──► WHOIS ──► Passive DNS ──► Social OSINT
                                        │
                           Playwright Wallet Harvester
                       (register → login → deposit form → wallet)
                                        │
                           crt.sh + VirusTotal + Shodan
                                        │
                           Blockchain Analysis (BTC/ETH/USDT)
                                        │
                           GPT-4o Intelligence Report
                                        │
                           Risk Score (0-100)
                                        │
                    ┌─────── Human Review ────────┐
                    │                             │
                  APPROVE                      REJECT
                    │
          Takedown Drafts + LE Package
          (Registrar · Hosting · IC3 · I4G)
```

| # | Script | What it does |
|---|--------|-------------|
| 1 | `discover_scams.py` | 15-source discovery — HYIP monitors, URLScan, PhishTank, OpenPhish, Telegram |
| 2 | `urlscan_lookup.py` | Infrastructure intel + visual clone detection |
| 3 | `whois_lookup.py` | Registrar, abuse contacts, SOA email (multi-method: python-whois + raw + RDAP) |
| 4 | `passive_dns.py` | pDNS pivot — CIRCL (free) + ZETAlytics — IP cluster + SOA attribution |
| 5 | `social_osint.py` | Deep scraping — wallets, phones, Telegram, social links, 6 pages |
| 5.5 | `wallet_harvester.py` | **Playwright headless Chrome** — full auth flow, deposit form submission |
| 6 | `cert_osint.py` | crt.sh subdomains + VirusTotal + Shodan |
| 7 | `blockchain.py` | BTC (blockchain.info → mempool.space → Blockchair) / ETH (Etherscan V2) / USDT-TRC20 |
| 8 | `report_generator.py` | GPT-4o intelligence summary |
| 9 | `risk_scorer.py` | Weighted 0-100 risk score with narrative breakdown |
| 10 | `takedown_drafter.py` | Formal abuse emails to registrar + hosting |
| 11 | `le_packager.py` | IC3-formatted LE referral package + evidence bundle |
| 12 | `network_graph.py` | D3.js force graph edge builder |
| — | `autonomous.py` | Autonomous discovery + investigation engine |
| — | `db.py` | PostgreSQL schema + all database operations |
| — | `agent.py` | Orchestrator — runs all stages end to end |
| — | `app.py` | Flask dashboard — intake, approvals, submissions |

---

## 🤖 Autonomous Mode

No bounty needed. The agent hunts scams on its own 24/7.

**Discovery Sources (15 total):**

| Source | Type |
|--------|------|
| tophyip.biz | HYIP Monitor |
| payinghyiponline.com | HYIP Monitor |
| invest-tracing.com | HYIP Monitor |
| bestemoneys.com | HYIP Monitor |
| phyip.com | HYIP Monitor |
| hyip.biz | HYIP Monitor |
| sqmonitor.com | HYIP Monitor |
| hyipbanker.com | HYIP Monitor |
| hothyips.com | HYIP Monitor |
| hyipmonitors24.net | HYIP Monitor |
| URLScan cryptoscam tag | Community-verified |
| CryptoScamDB | Crypto fraud DB |
| OpenPhish | Phishing feed |
| PhishTank | Crowdsourced phishing |
| Telegram channels | Scam promotion channels |

```bash
# See what's out there right now
python3 autonomous.py --discover

# Investigate top 10 automatically
python3 autonomous.py --count 10

# Run forever — new cycle every 4 hours
python3 autonomous.py --continuous --count 20 --interval 4

# Dry run — score and rank without investigating
python3 autonomous.py --dry-run --count 50
```

High-value finds (wallets with transaction history, VT flags, large IP clusters) are automatically flagged for submission.

---

## Stack

| Layer | Tech |
|-------|------|
| Language | Python 3.10+ |
| AI | OpenAI GPT-4o |
| Browser Automation | Playwright (Chromium) |
| Web | Flask + Gunicorn |
| Database | PostgreSQL |
| Deployment | Railway |
| DNS Intel | CIRCL Passive DNS · ZETAlytics |
| Domain Intel | URLScan.io · python-whois · crt.sh · RDAP |
| Threat Intel | VirusTotal · Shodan |
| Blockchain (BTC) | blockchain.info → mempool.space → Blockchair |
| Blockchain (ETH) | Etherscan V2 API → Blockchair |
| Blockchain (USDT) | TronScan → Blockchair TRON |
| OSINT | BeautifulSoup4 · requests |
| Visualization | D3.js network graph |

---

## API Keys

| Variable | Required | Free Tier | Source |
|----------|----------|-----------|--------|
| `OPENAI_API_KEY` | ✅ | Pay-per-use | [platform.openai.com](https://platform.openai.com) |
| `URLSCAN_API_KEY` | ✅ | Yes | [urlscan.io](https://urlscan.io) |
| `VIRUSTOTAL_API_KEY` | ✅ | Yes (4 req/min) | [virustotal.com](https://virustotal.com) |
| `SHODAN_API_KEY` | ✅ | Yes | [shodan.io](https://shodan.io) |
| `ETHERSCAN_API_KEY` | ✅ | Yes | [etherscan.io/apis](https://etherscan.io/apis) |
| `ZETALYTICS_API_KEY` | ⬜ | Course key | [zonecruncher.com](https://zonecruncher.com) |

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
# Fill in your API keys
```

Initialize PostgreSQL:

```bash
createdb scambusters
python3 -c "from scripts.db import init_db; init_db()"
```

Run the dashboard:

```bash
python3 app.py
# → http://localhost:5000
```

Run a direct investigation:

```bash
python3 agent.py stake2earn.app
```

---

## Architecture

```
┌─────────────────────────────────────────┐
│         PUBLIC (Railway)                │
│  Live stats · Network graph · Leaderboard│
│  REST API: /api/domain /api/wallet      │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         PRIVATE (local)                 │
│  Bounty intake · Pipeline · Approvals   │
│  Takedown drafts · LE packages          │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         POSTGRESQL                      │
│  bounties · investigations · wallets    │
│  threat_actors · network_edges          │
└─────────────────────────────────────────┘
```

---

## Changelog

### v2.0 (March 2026) — Current
- **Playwright Wallet Harvester** — headless Chrome registers fake account, handles query-param style sites (`/?a=signup`), logs in after registration, submits deposit form, extracts real BTC/ETH/USDT wallet addresses from behind authentication
- **Autonomous Discovery Engine** — 15-source scraper runs continuously, no bounty required, scores and prioritizes domains, auto-flags high-value finds
- **BTC Blockchain Fix** — migrated from Blockchair (rate limited) to blockchain.info primary with mempool.space + Blockchair fallback chain
- **ETH Blockchain Fix** — migrated from Etherscan V1 to Etherscan V2 API
- **USDT/TRC20 Fix** — TronScan fallback chain with Blockchair TRON as last resort
- **False positive filtering** — tightened wallet regex patterns (base58 BTC, exact SOL length, MD5 hash rejection)
- **PostgreSQL** — migrated from SQLite to PostgreSQL for production
- **Risk scorer** — now incorporates blockchain evidence (USD traced) into score
- **LE packages** — IC3-formatted narrative with victim loss figures
- **Public dashboard** — live leaderboard widget (I4G API), network graph, public stats
- **Railway deployment** — production deployed with auto-deploy from v2 branch

### v1.0 (Initial)
- 7-stage pipeline: URLScan → WHOIS → Passive DNS → Social OSINT → crt.sh/VT/Shodan → GPT-4o Report → Takedown Drafts
- SQLite database
- Flask dashboard
- Basic wallet extraction from HTML (no authentication)
- Blockchair BTC analysis

---

## OpSec

> ⚠️ Always investigate behind a VPN.  
> Never enter real personal information on scam sites.  
> Run wallet harvesting from a sandboxed environment when possible.  
> These are adversarial infrastructure targets — treat them accordingly.

---

## Branches

| Branch | Status | Description |
|--------|--------|-------------|
| `main` | Stable | v1.0 — 7-stage pipeline, SQLite |
| `v2` | Active | v2.0 — 9-stage pipeline, Playwright harvester, PostgreSQL, autonomous mode |

---

## Deployment (Railway)

```bash
# Set environment variables in Railway dashboard
# Deploy from v2 branch
railway up
```

`Procfile` and `railway.toml` included. Railway auto-detects Python and runs gunicorn.

---

## Based on

ScamBusters® curriculum — University of Tampa Center for Cybersecurity  
Methodology by [Intelligence For Good](https://intelligenceforgood.org) and UAB Cyber Forensics Research Laboratory (Gary Warner)

Built by **Elijah Beese** · University of Tampa · Army ROTC Cadet

---

<div align="center">

[![I4G Leaderboard](https://img.shields.io/badge/I4G-ScamBusters%20University-00d4aa?style=flat-square)](https://www.intelligenceforgood.org/scambusters-leaderboard)
[![UTampa Cyber Spartans](https://img.shields.io/badge/Team-UTampa%20Cyber%20Spartans-0099ff?style=flat-square)](https://www.intelligenceforgood.org/scambusters-leaderboard)

*Fighting scams, one takedown at a time.*

</div>
