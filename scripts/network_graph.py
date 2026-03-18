"""
network_graph.py — Build network edges from investigation data
Creates the graph structure for D3.js force-directed visualization.

Node types:
- domain   (scam sites)
- ip       (hosting infrastructure)
- wallet   (crypto addresses)
- actor    (threat actor / SOA email)
- asn      (hosting provider)

Edge types:
- hosted_on     domain → ip
- clone_of      domain → domain
- same_operator domain → actor (via SOA email)
- wallet_of     domain → wallet
- shares_ip     domain → domain (via shared IP)
- same_asn      domain → asn
"""

from scripts.db import add_edge


def build_graph_from_investigation(domain: str, investigation: dict):
    """
    Extract all relationships from an investigation and store as graph edges.
    These feed the public D3 network visualization.
    """
    urlscan = investigation.get("urlscan", {}) or {}
    whois   = investigation.get("whois", {}) or {}
    pdns    = investigation.get("passive_dns", {}) or {}
    social  = investigation.get("social_osint", {}) or {}
    bc      = investigation.get("blockchain", {}) or {}
    similar = investigation.get("similar_domains", []) or []

    primary_ip  = urlscan.get("primary_ip")
    asn_name    = urlscan.get("asn_name")
    soa_email   = whois.get("soa_email")
    registrar   = whois.get("registrar")

    # domain → IP
    if primary_ip:
        add_edge(domain, primary_ip, "hosted_on", 1.0,
                 {"asn": asn_name, "country": urlscan.get("country")})

    # domain → ASN
    if asn_name:
        add_edge(domain, asn_name, "same_asn", 0.5,
                 {"country": urlscan.get("country")})

    # domain → threat actor (SOA)
    if soa_email:
        add_edge(domain, soa_email, "same_operator", 2.0,
                 {"registrar": registrar})

    # SOA cluster: all domains sharing same SOA email
    for linked in (pdns.get("soa_cluster_domains") or [])[:50]:
        if linked != domain:
            add_edge(linked, soa_email, "same_operator", 2.0, {})
            add_edge(domain, linked, "soa_cluster", 1.5, {"via": "soa_email"})

    # domain → historical IPs
    for ip in (pdns.get("historical_ips") or [])[:10]:
        add_edge(domain, ip, "hosted_on", 0.8, {"type": "historical"})

    # Clone domains (URLScan visual similarity)
    for clone in similar[:30]:
        clone_domain = clone.get("domain")
        if clone_domain and clone_domain != domain:
            add_edge(domain, clone_domain, "clone_of", 1.2,
                     {"shared_template": True,
                      "clone_ip": clone.get("ip"),
                      "clone_asn": clone.get("asn")})
            if clone.get("ip") and clone.get("ip") == primary_ip:
                add_edge(domain, clone_domain, "shares_ip", 1.5, {})

    # IP pivot domains (pDNS)
    for linked in (pdns.get("ip_pivot_domains") or [])[:20]:
        if linked != domain:
            add_edge(domain, linked, "shares_ip", 1.0,
                     {"via": "ip_pivot"})

    # Wallet addresses
    for currency, wallets in (bc.get("by_currency") or {}).items():
        for w in wallets:
            if isinstance(w, dict) and w.get("address"):
                add_edge(domain, w["address"], "wallet_of", 1.0,
                         {"currency": currency,
                          "total_usd": w.get("total_received_usd", 0),
                          "tx_count": w.get("tx_count", 0)})

    # Social channels
    for platform, links in (social.get("social_links") or {}).items():
        for link in (links or [])[:5]:
            add_edge(domain, link, "promotes_via", 0.8,
                     {"platform": platform})


def get_graph_data(domain: str, depth: int = 2) -> dict:
    """
    Pull graph data from DB and format for D3.js.
    Returns nodes array and links array.
    """
    from scripts.db import get_graph_for_domain
    raw = get_graph_for_domain(domain, depth)

    # Assign visual properties to nodes
    node_styles = {
        "domain":  {"color": "#00d4aa", "size": 8,  "label": "scam site"},
        "ip":      {"color": "#0099ff", "size": 6,  "label": "IP address"},
        "wallet":  {"color": "#ff8c00", "size": 7,  "label": "wallet"},
        "actor":   {"color": "#ff3b5c", "size": 10, "label": "operator"},
        "asn":     {"color": "#9b6dff", "size": 5,  "label": "hosting"},
    }

    nodes = []
    for n in raw["nodes"]:
        style = node_styles.get(n["type"], node_styles["domain"])
        nodes.append({
            "id":    n["id"],
            "type":  n["type"],
            "label": n["id"][:30] + "..." if len(n["id"]) > 30 else n["id"],
            "color": style["color"],
            "size":  style["size"] + min(n.get("weight", 1), 5),
        })

    links = []
    edge_styles = {
        "hosted_on":    {"color": "#0099ff", "width": 1},
        "clone_of":     {"color": "#00d4aa", "width": 2},
        "same_operator":{"color": "#ff3b5c", "width": 3},
        "wallet_of":    {"color": "#ff8c00", "width": 2},
        "shares_ip":    {"color": "#9b6dff", "width": 1.5},
        "soa_cluster":  {"color": "#ff3b5c", "width": 1},
        "promotes_via": {"color": "#888780", "width": 1},
    }

    for e in raw["edges"]:
        style = edge_styles.get(e["type"], {"color": "#5a6a7a", "width": 1})
        links.append({
            "source": e["source"],
            "target": e["target"],
            "type":   e["type"],
            "color":  style["color"],
            "width":  style["width"] * e.get("weight", 1),
        })

    return {
        "nodes": nodes,
        "links": links,
        "center": domain,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(links),
            "depth": depth,
        }
    }
