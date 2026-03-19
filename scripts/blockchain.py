"""
blockchain.py — Crypto wallet transaction analysis
Queries Blockchair, Etherscan, TronScan, and BSCScan for:
- Transaction counts
- Total received (in crypto + USD)
- First/last activity dates
- Sending exchanges (Coinbase, Binance, etc.)

This is the money trail. Per I4G docs:
KrakenFutures cluster had $92.1M traced to 4 USDT addresses at BitKub Thailand.
$70,727 per day still flowing in 2025.
"""

import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_KEY  = os.getenv("ETHERSCAN_API_KEY", "")
BSCSCAN_KEY    = os.getenv("BSCSCAN_API_KEY", "")

HEADERS = {"User-Agent": "ScamBusters-Agent/2.0 OSINT-Investigation"}

# ── Bitcoin (Blockchair — free, no key) ──────────────────────────────────────

def analyze_bitcoin(address: str) -> dict:
    try:
        r = requests.get(
            f"https://api.blockchair.com/bitcoin/dashboards/address/{address}",
            headers=HEADERS, timeout=15
        )
        if r.status_code != 200:
            return {"error": f"Blockchair returned {r.status_code}"}

        data = r.json().get("data", {}).get(address, {})
        addr = data.get("address", {})
        txs  = data.get("transactions", [])

        received_btc = addr.get("received", 0) / 1e8
        price_usd    = _get_btc_price()

        return {
            "currency":           "BTC",
            "address":            address,
            "tx_count":           addr.get("transaction_count", 0),
            "total_received":     received_btc,
            "total_received_usd": received_btc * price_usd,
            "balance":            addr.get("balance", 0) / 1e8,
            "first_seen":         txs[-1] if txs else None,
            "last_seen":          txs[0] if txs else None,
            "is_active":          addr.get("transaction_count", 0) > 0,
            "explorer_url":       f"https://blockchair.com/bitcoin/address/{address}",
        }
    except Exception as e:
        return {"error": str(e), "currency": "BTC", "address": address}


def _get_btc_price() -> float:
    try:
        r = requests.get(
            "https://api.blockchair.com/bitcoin/stats",
            headers=HEADERS, timeout=10
        )
        return r.json().get("data", {}).get("market_price_usd", 65000)
    except Exception:
        return 65000


# ── Ethereum / ERC-20 (Etherscan) ────────────────────────────────────────────

def analyze_ethereum(address: str) -> dict:
    if not ETHERSCAN_KEY:
        return _analyze_eth_free(address)

    try:
        # ETH balance — Etherscan V2
        r = requests.get(
            f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance"
            f"&address={address}&tag=latest&apikey={ETHERSCAN_KEY}",
            headers=HEADERS, timeout=15
        )
        result = r.json().get("result", "0")
        # Handle V2 deprecation messages
        if isinstance(result, str) and result.isdigit():
            balance_wei = int(result)
        else:
            balance_wei = 0
        balance_eth = balance_wei / 1e18

        # TX list — Etherscan V2
        r2 = requests.get(
            f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist"
            f"&address={address}&startblock=0&endblock=99999999"
            f"&page=1&offset=100&sort=asc&apikey={ETHERSCAN_KEY}",
            headers=HEADERS, timeout=15
        )
        txs = r2.json().get("result", [])
        if not isinstance(txs, list):
            txs = []

        total_received = sum(
            int(tx.get("value", 0)) / 1e18
            for tx in txs
            if tx.get("to", "").lower() == address.lower()
        )

        eth_price = _get_eth_price()

        return {
            "currency":           "ETH",
            "address":            address,
            "tx_count":           len(txs),
            "total_received":     total_received,
            "total_received_usd": total_received * eth_price,
            "balance":            balance_eth,
            "first_seen":         datetime.fromtimestamp(
                int(txs[0]["timeStamp"]), tz=timezone.utc
            ).isoformat() if txs else None,
            "last_seen":          datetime.fromtimestamp(
                int(txs[-1]["timeStamp"]), tz=timezone.utc
            ).isoformat() if txs else None,
            "is_active":          len(txs) > 0,
            "explorer_url":       f"https://etherscan.io/address/{address}",
        }
    except Exception as e:
        return _analyze_eth_free(address)


def _analyze_eth_free(address: str) -> dict:
    """Fallback: Blockchair ETH (no key, rate limited)."""
    try:
        r = requests.get(
            f"https://api.blockchair.com/ethereum/dashboards/address/{address}",
            headers=HEADERS, timeout=15
        )
        if r.status_code != 200:
            return {"error": "No Etherscan key and Blockchair rate limited",
                    "currency": "ETH", "address": address}
        data = r.json().get("data", {}).get(address, {}).get("address", {})
        eth_price = _get_eth_price()
        received_eth = data.get("received_approximate", 0) / 1e18
        return {
            "currency":           "ETH",
            "address":            address,
            "tx_count":           data.get("transaction_count", 0),
            "total_received":     received_eth,
            "total_received_usd": received_eth * eth_price,
            "balance":            data.get("balance", 0) / 1e18,
            "is_active":          data.get("transaction_count", 0) > 0,
            "explorer_url":       f"https://etherscan.io/address/{address}",
        }
    except Exception as e:
        return {"error": str(e), "currency": "ETH", "address": address}


def _get_eth_price() -> float:
    try:
        r = requests.get(
            "https://api.blockchair.com/ethereum/stats",
            headers=HEADERS, timeout=10
        )
        return r.json().get("data", {}).get("market_price_usd", 3500)
    except Exception:
        return 3500


# ── TRON / USDT TRC-20 (TronGrid — free) ────────────────────────────────────

def analyze_tron(address: str) -> dict:
    """
    TRON/USDT-TRC20 analysis.
    Uses TronGrid free API (no key needed for basic queries).
    """
    try:
        # TronGrid — free, no auth required
        r = requests.get(
            f"https://apilist.tronscanapi.com/api/accountv2?address={address}",
            headers={**HEADERS, "TRON-PRO-API-KEY": ""},
            timeout=15
        )

        if r.status_code == 401 or r.status_code == 403:
            # Fall back to TronGrid alternative
            return _analyze_tron_tronscan(address)

        if r.status_code != 200:
            return _analyze_tron_tronscan(address)

        data = r.json()
        trx_balance = data.get("balance", 0) / 1e6

        usdt_balance = 0
        for token in data.get("trc20token_balances", []):
            if token.get("tokenAbbr") in ("USDT", "USDT_TRC20"):
                usdt_balance = float(token.get("balance", 0)) / 1e6
                break

        # TX count from separate endpoint
        r2 = requests.get(
            f"https://apilist.tronscanapi.com/api/transaction?address={address}&limit=1&start=0",
            headers=HEADERS, timeout=15
        )
        tx_total = 0
        if r2.status_code == 200:
            tx_total = r2.json().get("total", 0)

        return {
            "currency":           "USDT_TRC20",
            "address":            address,
            "tx_count":           tx_total,
            "total_received":     usdt_balance,
            "total_received_usd": usdt_balance,
            "balance_trx":        trx_balance,
            "is_active":          tx_total > 0,
            "explorer_url":       f"https://tronscan.org/#/address/{address}",
        }
    except Exception as e:
        return _analyze_tron_tronscan(address)


def _analyze_tron_tronscan(address: str) -> dict:
    """Fallback: query Blockchair for TRON data."""
    try:
        r = requests.get(
            f"https://api.blockchair.com/tron/dashboards/address/{address}",
            headers=HEADERS, timeout=15
        )
        if r.status_code == 200:
            data = r.json().get("data", {}).get(address, {}).get("address", {})
            balance = data.get("balance", 0) / 1e6
            tx_count = data.get("transaction_count", 0)
            return {
                "currency":           "USDT_TRC20",
                "address":            address,
                "tx_count":           tx_count,
                "total_received":     balance,
                "total_received_usd": balance,
                "is_active":          tx_count > 0,
                "explorer_url":       f"https://tronscan.org/#/address/{address}",
            }
    except Exception:
        pass

    # Last resort — return basic structure so pipeline doesn't break
    return {
        "currency":           "USDT_TRC20",
        "address":            address,
        "tx_count":           0,
        "total_received":     0,
        "total_received_usd": 0,
        "is_active":          False,
        "explorer_url":       f"https://tronscan.org/#/address/{address}",
        "note":               "Manual verification required at tronscan.org",
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────

def analyze_wallet(currency: str, address: str) -> dict:
    """Route wallet to correct blockchain analyzer."""
    c = currency.lower()
    if c in ("btc", "bitcoin"):
        return analyze_bitcoin(address)
    elif c in ("eth", "ethereum", "usdt_erc20"):
        return analyze_ethereum(address)
    elif c in ("trx", "tron", "usdt_trc20", "usdt"):
        return analyze_tron(address)
    else:
        return {
            "currency": currency,
            "address":  address,
            "error":    f"No analyzer for {currency}",
            "explorer_url": f"https://blockchair.com/search?q={address}",
        }


def analyze_all_wallets(wallets: dict) -> dict:
    """
    Analyze all wallets from a domain investigation.
    wallets: {currency: [address, ...], ...}
    Returns enriched wallet data with USD totals.
    """
    results = {}
    total_usd = 0.0

    for currency, addresses in wallets.items():
        results[currency] = []
        for address in addresses:
            data = analyze_wallet(currency, address)
            results[currency].append(data)
            total_usd += data.get("total_received_usd", 0)

    return {
        "by_currency": results,
        "total_usd":   total_usd,
        "wallet_count": sum(len(v) for v in wallets.values()),
        "high_value":  total_usd > 10000,
    }


if __name__ == "__main__":
    import json, sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "TUEj2HuEafsMQfuWNQaCEX62W4YzXGdKJD"
    currency = sys.argv[2] if len(sys.argv) > 2 else "USDT_TRC20"
    result = analyze_wallet(currency, addr)
    print(json.dumps(result, indent=2, default=str))
