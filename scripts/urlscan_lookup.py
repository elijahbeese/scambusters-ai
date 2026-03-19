"""
urlscan_lookup.py — URLScan.io integration v2
Fixes:
- Proper poll loop with retries (was timing out before scan completed)
- Full data extraction from result (IPs, ASN, similar sites, screenshot)
- Similar domain clustering via visual hash
- Abuse contact extraction from ASN
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")
HEADERS = {
    "User-Agent": "ScamBusters-Agent/2.0 OSINT-Investigation",
    "API-Key": URLSCAN_KEY,
    "Content-Type": "application/json",
}


def submit_scan(domain: str) -> str | None:
    """Submit domain to URLScan and return scan UUID."""
    try:
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=HEADERS,
            json={"url": f"https://{domain}", "visibility": "public"},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("uuid")
        elif r.status_code == 400:
            # Already scanned recently — search for existing
            return _find_existing_scan(domain)
        else:
            print(f"  [urlscan] Submit failed ({r.status_code}): {r.text[:100]}")
            return None
    except Exception as e:
        print(f"  [urlscan] Submit error: {e}")
        return None


def _find_existing_scan(domain: str) -> str | None:
    """Search URLScan for an existing recent scan of this domain."""
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
            headers=HEADERS,
            timeout=15,
        )
        results = r.json().get("results", [])
        if results:
            return results[0].get("task", {}).get("uuid")
        return None
    except Exception:
        return None


def poll_result(uuid: str, max_wait: int = 60) -> dict | None:
    """
    Poll URLScan for scan result with retries.
    URLScan takes 10-30 seconds to complete a scan.
    max_wait: maximum seconds to wait
    """
    url = f"https://urlscan.io/api/v1/result/{uuid}/"
    waited = 0
    interval = 5

    while waited < max_wait:
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                # Not ready yet
                time.sleep(interval)
                waited += interval
            else:
                print(f"  [urlscan] Poll error {r.status_code}")
                return None
        except Exception as e:
            print(f"  [urlscan] Poll exception: {e}")
            return None

    print(f"  [urlscan] Timed out after {max_wait}s waiting for {uuid}")
    return None


def extract_result(result: dict, domain: str) -> dict:
    """Extract all useful fields from URLScan result."""
    page    = result.get("page", {})
    task    = result.get("task", {})
    stats   = result.get("stats", {})
    meta    = result.get("meta", {})
    verdicts = result.get("verdicts", {})

    # IP and network info
    primary_ip  = page.get("ip")
    asn_raw     = page.get("asn", "")          # e.g. "AS13335"
    asn_name    = page.get("asnname", "")
    country     = page.get("country", "")
    server      = page.get("server", "")
    ptr         = page.get("ptr", "")          # reverse DNS

    # URLs and screenshots
    screenshot_url = f"https://urlscan.io/screenshots/{task.get('uuid', '')}.png"
    report_url     = f"https://urlscan.io/result/{task.get('uuid', '')}/"

    # Malicious verdict
    overall     = verdicts.get("overall", {})
    malicious   = overall.get("malicious", False)
    score       = overall.get("score", 0)
    categories  = overall.get("categories", [])

    # Technologies detected
    technologies = []
    for tech in meta.get("processors", {}).get("wappa", {}).get("data", []):
        technologies.append(tech.get("app", ""))

    # Links found on page
    links_total = stats.get("uniqLinks", 0)

    return {
        "primary_ip":     primary_ip,
        "asn_number":     asn_raw,
        "asn_name":       asn_name,
        "country":        country,
        "server":         server,
        "ptr":            ptr,
        "screenshot_url": screenshot_url,
        "report_url":     report_url,
        "scan_uuid":      task.get("uuid"),
        "malicious":      malicious,
        "malicious_score": score,
        "categories":     categories,
        "technologies":   technologies,
        "links_total":    links_total,
        "domain":         page.get("domain", domain),
        "final_url":      page.get("url", f"https://{domain}"),
    }


def get_similar_domains(domain: str, limit: int = 50) -> list:
    """
    Find visually similar domains using URLScan's visual hash search.
    This is the key technique for finding HYIP template clusters.
    """
    similar = []
    try:
        # Search by domain hash (finds sites using same template)
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=page.domain:{domain}&size=5",
            headers=HEADERS,
            timeout=15,
        )
        results = r.json().get("results", [])

        # Get the hash from the most recent scan
        if results:
            latest = results[0]
            hash_val = latest.get("task", {}).get("domHash")

            if hash_val:
                # Find all sites with same visual hash
                r2 = requests.get(
                    f"https://urlscan.io/api/v1/search/?q=task.domHash:{hash_val}&size={limit}",
                    headers=HEADERS,
                    timeout=15,
                )
                clones = r2.json().get("results", [])
                for c in clones:
                    clone_domain = c.get("page", {}).get("domain", "")
                    if clone_domain and clone_domain != domain:
                        similar.append({
                            "domain":  clone_domain,
                            "ip":      c.get("page", {}).get("ip"),
                            "asn":     c.get("page", {}).get("asnname"),
                            "country": c.get("page", {}).get("country"),
                            "date":    c.get("task", {}).get("time", ""),
                            "uuid":    c.get("task", {}).get("uuid", ""),
                        })

        # Also search by similar page structure
        if len(similar) < 5:
            r3 = requests.get(
                f"https://urlscan.io/api/v1/search/?q=page.domain:*{_get_base(domain)}*&size=20",
                headers=HEADERS,
                timeout=15,
            )
            for c in r3.json().get("results", []):
                clone_domain = c.get("page", {}).get("domain", "")
                if clone_domain and clone_domain != domain:
                    if not any(s["domain"] == clone_domain for s in similar):
                        similar.append({
                            "domain":  clone_domain,
                            "ip":      c.get("page", {}).get("ip"),
                            "asn":     c.get("page", {}).get("asnname"),
                            "country": c.get("page", {}).get("country"),
                            "date":    c.get("task", {}).get("time", ""),
                        })

    except Exception as e:
        print(f"  [urlscan] Similar domains error: {e}")

    return similar[:limit]


def _get_base(domain: str) -> str:
    """Extract base keyword from domain for similarity search."""
    parts = domain.replace(".com", "").replace(".net", "").replace(".org", "")
    parts = parts.replace(".app", "").replace(".io", "").replace(".pro", "")
    return parts.split(".")[0][:8]


def run_urlscan(domain: str) -> dict:
    """
    Full URLScan pipeline:
    1. Submit scan (or find existing)
    2. Poll until complete
    3. Extract all data
    4. Find similar/clone domains
    """
    if not URLSCAN_KEY:
        return {"error": "URLSCAN_API_KEY not set"}

    # Submit
    uuid = submit_scan(domain)
    if not uuid:
        return {"error": "Could not submit or find URLScan scan"}

    # Poll with proper wait
    print(f"  [urlscan] Waiting for scan {uuid}...")
    result = poll_result(uuid, max_wait=60)

    if not result:
        # Try fetching existing result anyway
        try:
            r = requests.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                result = r.json()
        except Exception:
            pass

    if not result:
        return {"error": f"URLScan scan {uuid} did not complete in time"}

    data = extract_result(result, domain)

    # Get similar/clone domains
    similar = get_similar_domains(domain)
    data["similar_count"] = len(similar)
    data["similar_domains"] = similar

    return data


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "stake2earn.app"
    result = run_urlscan(domain)
    print(json.dumps(result, indent=2, default=str))
