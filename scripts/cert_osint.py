"""
cert_osint.py — Deep OSINT layer
- crt.sh: Certificate transparency logs → subdomain discovery
- Shodan: Open ports, banners, exposed admin panels
- VirusTotal: Malicious/suspicious vendor verdicts
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

SHODAN_KEY   = os.getenv("SHODAN_API_KEY", "")
VT_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")

HEADERS = {"User-Agent": "ScamBusters-Agent/2.0 OSINT-Investigation"}


# ── Certificate Transparency (crt.sh — free) ─────────────────────────────────

def query_crtsh(domain: str) -> dict:
    """
    Query crt.sh for SSL certificates issued for a domain.
    Reveals subdomains, admin panels, API endpoints the scammer registered.
    Often finds: admin.domain.com, api.domain.com, login.domain.com
    """
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers=HEADERS, timeout=15
        )
        if r.status_code != 200:
            return {"error": f"crt.sh returned {r.status_code}"}

        certs = r.json()
        subdomains = set()
        issuers = set()
        earliest = None
        latest = None

        for cert in certs:
            name = cert.get("name_value", "").strip()
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub != domain and domain in sub:
                    subdomains.add(sub)

            issuer = cert.get("issuer_name", "")
            if issuer:
                issuers.add(issuer)

            not_before = cert.get("not_before", "")
            not_after  = cert.get("not_after", "")
            if not_before:
                if not earliest or not_before < earliest:
                    earliest = not_before
            if not_after:
                if not latest or not_after > latest:
                    latest = not_after

        return {
            "subdomains": sorted(list(subdomains)),
            "subdomain_count": len(subdomains),
            "cert_count": len(certs),
            "issuers": list(issuers)[:5],
            "first_cert": earliest,
            "latest_cert": latest,
            "note": f"{len(subdomains)} subdomains found via {len(certs)} certificates",
        }
    except Exception as e:
        return {"error": str(e)}


# ── Shodan (requires free API key) ───────────────────────────────────────────

def query_shodan(ip: str) -> dict:
    """
    Query Shodan for open ports, banners, and service info on a given IP.
    Scam site hosting often has exposed admin panels, database ports,
    or misconfigured servers that reveal infrastructure details.
    """
    if not SHODAN_KEY:
        return {"error": "SHODAN_API_KEY not set — sign up free at shodan.io"}

    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}",
            headers=HEADERS, timeout=15
        )
        if r.status_code == 404:
            return {"ip": ip, "note": "No Shodan data for this IP"}
        if r.status_code != 200:
            return {"error": f"Shodan returned {r.status_code}"}

        data = r.json()
        ports = data.get("ports", [])
        services = []

        for item in data.get("data", []):
            port = item.get("port")
            product = item.get("product", "")
            version = item.get("version", "")
            banner  = (item.get("data", "") or "")[:100]
            services.append({
                "port": port,
                "product": product,
                "version": version,
                "banner_snippet": banner,
            })

        # Flag suspicious ports
        suspicious_ports = []
        for port in ports:
            if port in (3306, 5432, 27017, 6379):
                suspicious_ports.append(f"{port} (database exposed!)")
            elif port in (8080, 8443, 8888):
                suspicious_ports.append(f"{port} (admin panel?)")
            elif port == 21:
                suspicious_ports.append("21 (FTP — potential data exfil)")

        return {
            "ip": ip,
            "org": data.get("org"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "open_ports": ports,
            "port_count": len(ports),
            "services": services[:10],
            "suspicious_ports": suspicious_ports,
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "os": data.get("os"),
            "last_update": data.get("last_update"),
            "vulns": list(data.get("vulns", {}).keys())[:10],
        }
    except Exception as e:
        return {"error": str(e), "ip": ip}


# ── VirusTotal ────────────────────────────────────────────────────────────────

def query_virustotal_domain(domain: str) -> dict:
    """
    Query VirusTotal for domain reputation.
    Returns vendor malicious/suspicious/harmless vote counts.
    """
    if not VT_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set — sign up free at virustotal.com"}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={**HEADERS, "x-apikey": VT_KEY},
            timeout=15
        )
        if r.status_code != 200:
            return {"error": f"VirusTotal returned {r.status_code}"}

        data = r.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        # Get names of engines that flagged it
        results = attrs.get("last_analysis_results", {})
        flagging_engines = [
            {"engine": k, "category": v.get("category"), "result": v.get("result")}
            for k, v in results.items()
            if v.get("category") in ("malicious", "suspicious")
        ][:15]

        categories = attrs.get("categories", {})
        tags = attrs.get("tags", [])

        return {
            "domain": domain,
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "harmless_votes": harmless,
            "undetected": undetected,
            "total_engines": malicious + suspicious + harmless + undetected,
            "flagging_engines": flagging_engines,
            "categories": categories,
            "tags": tags,
            "reputation": attrs.get("reputation", 0),
            "vt_url": f"https://www.virustotal.com/gui/domain/{domain}",
            "is_malicious": malicious >= 2,
        }
    except Exception as e:
        return {"error": str(e), "domain": domain}


def query_virustotal_ip(ip: str) -> dict:
    """Query VirusTotal for IP reputation."""
    if not VT_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={**HEADERS, "x-apikey": VT_KEY},
            timeout=15
        )
        if r.status_code != 200:
            return {"error": f"VirusTotal returned {r.status_code}"}
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "reputation": data.get("reputation", 0),
            "country": data.get("country"),
            "asn": data.get("asn"),
            "as_owner": data.get("as_owner"),
        }
    except Exception as e:
        return {"error": str(e)}


def run_cert_osint(domain: str, ip: str = None) -> dict:
    """Run full deep OSINT layer."""
    result = {
        "crtsh": query_crtsh(domain),
        "virustotal": query_virustotal_domain(domain),
    }

    if ip:
        result["shodan"] = query_shodan(ip)
        result["vt_ip"]  = query_virustotal_ip(ip)

    return result


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_cert_osint(domain)
    print(json.dumps(result, indent=2))
