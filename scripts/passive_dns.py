"""
passive_dns.py — Passive DNS pivot v2
Fixes:
- ZETAlytics query format corrected (was sending wrong parameters)
- CIRCL free pDNS as primary fallback
- SOA email cluster lookup (find all domains with same SOA)
- IP pivot (find all domains on same IP)
- Historical IP extraction
- MX record extraction for email infrastructure pivot
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

ZETALYTICS_KEY = os.getenv("ZETALYTICS_API_KEY", "")
HEADERS = {"User-Agent": "ScamBusters-Agent/2.0 OSINT-Investigation"}


# ── CIRCL Passive DNS (free, no auth) ─────────────────────────────────────────

def query_circl(domain: str) -> dict:
    """
    Query CIRCL passive DNS — free, reliable, no API key needed.
    Returns historical IPs, linked domains, and first/last seen dates.
    """
    result = {
        "historical_ips": [],
        "linked_domains": [],
        "first_seen": None,
        "last_seen": None,
    }

    try:
        r = requests.get(
            f"https://www.circl.lu/pdns/query/{domain}",
            headers={**HEADERS, "Accept": "application/json"},
            timeout=15
        )
        if r.status_code != 200:
            return result

        records = []
        for line in r.text.strip().split("\n"):
            if line.strip():
                try:
                    import json
                    records.append(json.loads(line))
                except Exception:
                    pass

        ips = set()
        domains = set()
        times = []

        for rec in records:
            rtype = rec.get("rrtype", "")
            rdata = rec.get("rdata", "")
            rrname = rec.get("rrname", "").rstrip(".")

            if rtype == "A" and rdata:
                ips.add(rdata)
            if rtype in ("CNAME", "NS") and rdata:
                domains.add(rdata.rstrip("."))

            if rec.get("time_first"):
                times.append(rec["time_first"])
            if rec.get("time_last"):
                times.append(rec["time_last"])

        result["historical_ips"] = list(ips)
        result["linked_domains"] = list(domains - {domain})
        if times:
            result["first_seen"] = min(times)
            result["last_seen"] = max(times)

    except Exception as e:
        print(f"  [pdns] CIRCL error: {e}")

    return result


# ── ZETAlytics (course API key) ───────────────────────────────────────────────

def query_zetalytics_domain(domain: str) -> dict:
    """
    Query ZETAlytics for domain passive DNS history.
    ZETAlytics is the premium tool used in the I4G curriculum.
    """
    if not ZETALYTICS_KEY:
        return {}

    result = {
        "historical_ips": [],
        "linked_domains": [],
        "soa_cluster_domains": [],
        "ip_pivot_domains": [],
        "mx_records": [],
        "ns_records": [],
    }

    try:
        # Domain history query
        r = requests.get(
            "https://zonecruncher.com/api/v1/history",
            params={
                "q": domain,
                "token": ZETALYTICS_KEY,
            },
            headers=HEADERS,
            timeout=20
        )

        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])

            for rec in results:
                qtype = rec.get("qtype", "")
                value = rec.get("value", "")

                if qtype == "A" and value:
                    if value not in result["historical_ips"]:
                        result["historical_ips"].append(value)
                elif qtype == "MX" and value:
                    result["mx_records"].append(value)
                elif qtype == "NS" and value:
                    result["ns_records"].append(value)

    except Exception as e:
        print(f"  [pdns] ZETAlytics domain query error: {e}")

    return result


def query_zetalytics_soa(soa_email: str) -> list:
    """
    Query ZETAlytics for all domains with the same SOA email.
    This is the KEY threat actor attribution technique from I4G curriculum.
    Same SOA email = same operator running multiple scam sites.
    """
    if not ZETALYTICS_KEY or not soa_email:
        return []

    try:
        r = requests.get(
            "https://zonecruncher.com/api/v1/email",
            params={
                "q": soa_email,
                "token": ZETALYTICS_KEY,
            },
            headers=HEADERS,
            timeout=20
        )

        if r.status_code == 200:
            data = r.json()
            domains = []
            for rec in data.get("results", []):
                d = rec.get("domain", "").rstrip(".")
                if d and d not in domains:
                    domains.append(d)
            return domains
        else:
            print(f"  [pdns] ZETAlytics SOA query returned {r.status_code}")
            return []

    except Exception as e:
        print(f"  [pdns] ZETAlytics SOA error: {e}")
        return []


def query_zetalytics_ip(ip: str) -> list:
    """
    Find all domains that have resolved to this IP.
    IP pivot = find all scam sites on same hosting.
    """
    if not ZETALYTICS_KEY or not ip:
        return []

    try:
        r = requests.get(
            "https://zonecruncher.com/api/v1/ip",
            params={
                "q": ip,
                "token": ZETALYTICS_KEY,
            },
            headers=HEADERS,
            timeout=20
        )

        if r.status_code == 200:
            data = r.json()
            domains = []
            for rec in data.get("results", []):
                d = rec.get("domain", "").rstrip(".")
                if d and d not in domains:
                    domains.append(d)
            return domains
        return []

    except Exception as e:
        print(f"  [pdns] ZETAlytics IP pivot error: {e}")
        return []


def query_hackertarget_ip(ip: str) -> list:
    """
    Free IP-to-hostnames lookup via HackerTarget API.
    Fallback when ZETAlytics fails or has no results.
    """
    if not ip:
        return []

    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            headers=HEADERS,
            timeout=15
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            return [d.strip() for d in r.text.strip().split("\n") if d.strip()]
        return []
    except Exception:
        return []


def run_passive_dns(domain: str, soa_email: str = None, primary_ip: str = None) -> dict:
    """
    Full passive DNS pipeline:
    1. CIRCL free lookup (always)
    2. ZETAlytics domain history
    3. SOA email cluster (if soa_email provided)
    4. IP pivot (if primary_ip provided)
    5. HackerTarget IP reverse (free fallback)
    """
    result = {
        "source":             "CIRCL + ZETAlytics",
        "historical_ips":     [],
        "linked_domains":     [],
        "soa_cluster_domains": [],
        "ip_pivot_domains":   [],
        "mx_records":         [],
        "soa_records":        [],
    }

    # CIRCL (free, always run)
    circl = query_circl(domain)
    result["historical_ips"].extend(circl.get("historical_ips", []))
    result["linked_domains"].extend(circl.get("linked_domains", []))

    # ZETAlytics domain history
    if ZETALYTICS_KEY:
        zeta = query_zetalytics_domain(domain)
        for ip in zeta.get("historical_ips", []):
            if ip not in result["historical_ips"]:
                result["historical_ips"].append(ip)
        result["mx_records"].extend(zeta.get("mx_records", []))

        # SOA cluster — the I4G killer feature
        if soa_email:
            soa_domains = query_zetalytics_soa(soa_email)
            result["soa_cluster_domains"] = [
                d for d in soa_domains if d != domain
            ]
            print(f"  [pdns] SOA cluster: {len(result['soa_cluster_domains'])} domains linked to {soa_email}")

        # IP pivot
        if primary_ip:
            ip_domains = query_zetalytics_ip(primary_ip)
            result["ip_pivot_domains"] = [
                d for d in ip_domains if d != domain
            ]
            print(f"  [pdns] IP pivot: {len(result['ip_pivot_domains'])} domains on {primary_ip}")

    # HackerTarget IP reverse (free fallback for IP pivot)
    if primary_ip and not result["ip_pivot_domains"]:
        ht_domains = query_hackertarget_ip(primary_ip)
        result["ip_pivot_domains"] = [d for d in ht_domains if d != domain]

    # Deduplicate
    result["historical_ips"]     = list(set(result["historical_ips"]))
    result["linked_domains"]     = list(set(result["linked_domains"]))
    result["ip_pivot_domains"]   = list(set(result["ip_pivot_domains"]))
    result["soa_cluster_domains"] = list(set(result["soa_cluster_domains"]))

    return result


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "stake2earn.app"
    soa    = sys.argv[2] if len(sys.argv) > 2 else None
    ip     = sys.argv[3] if len(sys.argv) > 3 else None
    result = run_passive_dns(domain, soa_email=soa, primary_ip=ip)
    print(json.dumps(result, indent=2, default=str))
