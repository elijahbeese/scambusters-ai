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
💰  Blockchain analysis — wallet transaction history, USD amounts traced on-chain
📡  Social OSINT — Telegram channels, WhatsApp groups, Google Dork queries
🤖  GPT-4o — structured intelligence report
📊  Risk scoring — weighted 0-100 score (MINIMAL / LOW / MEDIUM / HIGH / CRITICAL)
📨  Takedown emails — registrar + hosting provider (human-approved only)
🏛️  Law enforcement package — IC3-formatted narrative + evidence bundle
🕸️  Network graph — D3.js force graph connecting domains, IPs, wallets, operators
```

---

## Pipeline

```
HYIP Monitors + URLScan Tag ──► Discord Bounty Intake
                                        │
                                        ▼
              URLScan ──► WHOIS ──► Passive DNS ──► Social OSINT
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
| 1 | `discover_scams.py` | Scrapes HYIP monitor sites + URLScan cryptoscam tag |
| 2 | `urlscan_lookup.py` | Infrastructure intel + visual clone discovery |
| 3 | `whois_lookup.py` | Registrar, abuse contacts, SOA email |
| 4 | `passive_dns.py` | pDNS pivot — CIRCL (free) or ZETAlytics (premium) |
| 5 | `social_osint.py` | Social links, wallet extraction, Google Dorks |
| 6 | `cert_osint.py` | crt.sh subdomains + VirusTotal + Shodan |
| 7 | `blockchain.py` | BTC/ETH/USDT-TRC20 transaction history + USD totals |
| 8 | `report_generator.py` | GPT-4o intelligence summary |
| 9 | `risk_scorer.py` | Weighted risk score with breakdown |
| 10 | `takedown_drafter.py` | Formal abuse emails — fires after approval only |
| 11 | `le_packager.py` | IC3-formatted law enforcement referral package |
| 12 | `network_graph.py` | D3.js force graph edge builder |
| 13 | `scheduler.py` | Proactive discovery — no bounty needed |
| — | `db.py` | PostgreSQL schema + all database operations |
| — | `agent.py` | Orchestrator — runs all stages end to end |
| — | `app.py` | Private Flask dashboard — bounty intake + approvals |
| — | `templates/public.html` | Public dashboard — live stats + network graph + I4G leaderboard |

---

## Stack

| Layer | Tech |
|-------|------|
| Language | Python 3.10+ |
| AI | OpenAI GPT-4o |
| Web | Flask + Gunicorn |
| Database | PostgreSQL |
| Deployment | Railway |
| DNS Intel | CIRCL Passive DNS (free) · ZETAlytics (optional) |
| Domain Intel | URLScan.io · python-whois · crt.sh |
| Threat Intel | VirusTotal · Shodan |
| Blockchain | Blockchair · Etherscan · TronScan |
| OSINT | BeautifulSoup4 · requests · D3.js |

---

## API Keys

| Key | Required | Free tier | Get it |
|-----|----------|-----------|--------|
| `OPENAI_API_KEY` | ✅ | Pay-per-use | [platform.openai.com](https://platform.openai.com) |
| `URLSCAN_API_KEY` | ✅ | Yes | [urlscan.io](https://urlscan.io) |
| `VIRUSTOTAL_API_KEY` | ✅ | Yes (4 req/min) | [virustotal.com](https://virustotal.com) |
| `SHODAN_API_KEY` | ✅ | Yes | [shodan.io](https://shodan.io) |
| `ETHERSCAN_API_KEY` | ✅ | Yes | [etherscan.io/apis](https://etherscan.io/apis) |
| `HUNTER_API_KEY` | ⬜ | Yes | [hunter.io](https://hunter.io) |
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
cp .env_example .env
# Fill in your API keys
```

Initialize PostgreSQL:

```bash
createdb scambusters
python3 -c "from scripts.db import init_db; init_db()"
```

Run the private dashboard:

```bash
python3 app.py
# Open http://localhost:5000
# Paste a Discord bounty → investigate → approve → submit
```

Run a direct investigation:

```bash
python3 agent.py example-scam-domain.com
```

Run proactive discovery:

```bash
python3 scripts/scheduler.py
```

---

## Branches

| Branch | Description |
|--------|-------------|
| `main` | v1.0 — stable, 7-stage pipeline, SQLite, Flask UI |
| `v2` | v2.0 — 9-stage pipeline, blockchain analysis, PostgreSQL, public dashboard, LE packages, network graph |

---

## Deployment (Railway)

```bash
# Set environment variables in Railway dashboard
# Deploy from v2 branch
railway up
```

The `Procfile` and `railway.toml` are included. Railway auto-detects Python and runs gunicorn.

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

## OpSec

> ⚠️ Always investigate behind a VPN.
> Never enter real personal information on scam sites.
> Run wallet harvesting from a sandboxed VM.
> These are adversarial infrastructure targets — treat them accordingly.

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
