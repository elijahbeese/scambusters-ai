"""
risk_scorer.py — Automated risk scoring engine
Produces a weighted 0-100 score and CRITICAL/HIGH/MEDIUM/LOW/MINIMAL rating.

Scoring factors:
- Blockchain: total USD received, tx count, active status       (40 pts max)
- Infrastructure: clone count, IP pivot domains, template age   (20 pts max)
- Social: Telegram/WhatsApp presence, member counts             (15 pts max)
- Domain: age, registrar reputation, SOA cluster size           (15 pts max)
- VirusTotal: malicious verdicts                                (10 pts max)
"""


def score_investigation(investigation: dict) -> dict:
    breakdown = {}
    total = 0

    # ── Blockchain score (40 pts) ─────────────────────────────────────────────
    blockchain = investigation.get("blockchain", {})
    bc_score = 0
    total_usd = 0

    if isinstance(blockchain, dict):
        total_usd = blockchain.get("total_usd", 0)
        wallet_count = blockchain.get("wallet_count", 0)
        high_value = blockchain.get("high_value", False)

        if total_usd >= 1_000_000:    bc_score += 40
        elif total_usd >= 100_000:    bc_score += 32
        elif total_usd >= 10_000:     bc_score += 24
        elif total_usd >= 1_000:      bc_score += 16
        elif total_usd > 0:           bc_score += 8

        if wallet_count >= 10:        bc_score = min(bc_score + 5, 40)
        elif wallet_count >= 5:       bc_score = min(bc_score + 2, 40)

    breakdown["blockchain"] = {
        "score": bc_score,
        "max": 40,
        "total_usd": total_usd,
        "note": f"${total_usd:,.0f} traced" if total_usd > 0 else "No blockchain data",
    }
    total += bc_score

    # ── Infrastructure score (20 pts) ─────────────────────────────────────────
    infra_score = 0
    urlscan = investigation.get("urlscan", {}) or {}
    pdns = investigation.get("passive_dns", {}) or {}
    similar = investigation.get("similar_domains", []) or []

    clone_count = len(similar)
    linked_count = len(pdns.get("linked_domains", []) or [])
    ip_pivot_count = len(pdns.get("ip_pivot_domains", []) or [])
    soa_cluster = len(pdns.get("soa_cluster_domains", []) or [])

    if clone_count >= 50:      infra_score += 10
    elif clone_count >= 20:    infra_score += 7
    elif clone_count >= 5:     infra_score += 4
    elif clone_count >= 1:     infra_score += 2

    if soa_cluster >= 100:     infra_score += 6
    elif soa_cluster >= 50:    infra_score += 4
    elif soa_cluster >= 10:    infra_score += 2

    if ip_pivot_count >= 20:   infra_score += 4
    elif ip_pivot_count >= 5:  infra_score += 2

    infra_score = min(infra_score, 20)
    breakdown["infrastructure"] = {
        "score": infra_score,
        "max": 20,
        "clone_count": clone_count,
        "soa_cluster": soa_cluster,
        "note": f"{clone_count} clones, {soa_cluster} SOA-linked domains",
    }
    total += infra_score

    # ── Social score (15 pts) ─────────────────────────────────────────────────
    social_score = 0
    social = investigation.get("social_osint", {}) or {}
    social_links = social.get("social_links", {}) or {}

    telegram_links = social_links.get("telegram", [])
    whatsapp_links = social_links.get("whatsapp", [])
    fb_links = social_links.get("facebook", [])
    tiktok_links = social_links.get("tiktok", [])

    if telegram_links:   social_score += 6
    if whatsapp_links:   social_score += 5
    if fb_links:         social_score += 3
    if tiktok_links:     social_score += 3
    if social_links.get("twitter") or social_links.get("instagram"):
        social_score += 2

    social_score = min(social_score, 15)
    breakdown["social"] = {
        "score": social_score,
        "max": 15,
        "telegram": len(telegram_links),
        "whatsapp": len(whatsapp_links),
        "note": f"Telegram:{len(telegram_links)} WhatsApp:{len(whatsapp_links)} FB:{len(fb_links)}",
    }
    total += social_score

    # ── Domain score (15 pts) ─────────────────────────────────────────────────
    domain_score = 0
    whois = investigation.get("whois", {}) or {}
    creation_date = whois.get("creation_date", "")
    soa_email = whois.get("soa_email", "")
    registrar = (whois.get("registrar") or "").lower()

    # Young domains are more suspicious
    if creation_date:
        try:
            from datetime import datetime
            created = datetime.fromisoformat(str(creation_date).split("+")[0].strip())
            age_days = (datetime.utcnow() - created).days
            if age_days < 30:     domain_score += 8
            elif age_days < 90:   domain_score += 5
            elif age_days < 365:  domain_score += 2
        except Exception:
            pass

    # Cheap registrars commonly abused by scammers
    cheap_registrars = ["namecheap", "namesilo", "cosmotown", "webnic", "porkbun"]
    if any(r in registrar for r in cheap_registrars):
        domain_score += 4

    if soa_email:
        domain_score += 3  # SOA email present = better attribution

    domain_score = min(domain_score, 15)
    breakdown["domain"] = {
        "score": domain_score,
        "max": 15,
        "registrar": whois.get("registrar"),
        "soa_email": soa_email or "not found",
        "note": f"Registered: {creation_date or 'unknown'}",
    }
    total += domain_score

    # ── VirusTotal score (10 pts) ─────────────────────────────────────────────
    vt_score_pts = 0
    vt = investigation.get("virustotal", {}) or {}
    malicious = vt.get("malicious_votes", 0)
    suspicious = vt.get("suspicious_votes", 0)
    vt_total = malicious + suspicious

    if vt_total >= 10:     vt_score_pts += 10
    elif vt_total >= 5:    vt_score_pts += 7
    elif vt_total >= 2:    vt_score_pts += 4
    elif vt_total >= 1:    vt_score_pts += 2

    breakdown["virustotal"] = {
        "score": vt_score_pts,
        "max": 10,
        "malicious": malicious,
        "suspicious": suspicious,
        "note": f"{vt_total} vendor detections",
    }
    total += vt_score_pts

    # ── Final rating ──────────────────────────────────────────────────────────
    total = min(total, 100)

    if total >= 80:     level = "CRITICAL"
    elif total >= 60:   level = "HIGH"
    elif total >= 40:   level = "MEDIUM"
    elif total >= 20:   level = "LOW"
    else:               level = "MINIMAL"

    return {
        "score": total,
        "level": level,
        "breakdown": breakdown,
        "summary": _build_summary(total, level, breakdown),
    }


def _build_summary(score: int, level: str, breakdown: dict) -> str:
    parts = []
    bc = breakdown.get("blockchain", {})
    if bc.get("total_usd", 0) > 0:
        parts.append(f"${bc['total_usd']:,.0f} traced on-chain")

    infra = breakdown.get("infrastructure", {})
    if infra.get("clone_count", 0) > 0:
        parts.append(f"{infra['clone_count']} site clones identified")
    if infra.get("soa_cluster", 0) > 0:
        parts.append(f"{infra['soa_cluster']} domains linked to same operator")

    social = breakdown.get("social", {})
    if social.get("telegram", 0) > 0:
        parts.append(f"active Telegram channel")

    vt = breakdown.get("virustotal", {})
    if vt.get("malicious", 0) > 0:
        parts.append(f"{vt['malicious']} AV vendors flagged malicious")

    if not parts:
        parts = ["Limited active infrastructure detected"]

    return f"{level} ({score}/100) — " + " · ".join(parts)


if __name__ == "__main__":
    import json
    mock = {
        "blockchain": {"total_usd": 245000, "wallet_count": 4, "high_value": True},
        "similar_domains": [{"domain": f"clone{i}.com"} for i in range(23)],
        "passive_dns": {"soa_cluster_domains": [f"d{i}.com" for i in range(67)]},
        "social_osint": {"social_links": {"telegram": ["https://t.me/scam"], "whatsapp": []}},
        "whois": {"registrar": "Namecheap", "creation_date": "2024-11-15", "soa_email": "bad@gmail.com"},
        "virustotal": {"malicious_votes": 7, "suspicious_votes": 2},
    }
    result = score_investigation(mock)
    print(json.dumps(result, indent=2))
