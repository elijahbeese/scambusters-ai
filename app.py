"""
app.py — ScamBusters Agent v2.0
Full Flask application — private investigator dashboard + public intelligence portal.

Routes:
  PUBLIC  GET  /                    → public dashboard (live stats + network graph + leaderboard)
  PUBLIC  GET  /api/stats           → live stats JSON
  PUBLIC  GET  /api/graph/full      → full network graph JSON
  PUBLIC  GET  /api/domain/<domain> → domain intelligence JSON
  PUBLIC  GET  /health              → Railway health check

  PRIVATE GET  /dashboard           → bounty board
  PRIVATE GET  /intake              → paste bounty form
  PRIVATE POST /intake              → parse + queue bounty
  PRIVATE GET  /bounty/<id>         → bounty detail + pipeline trigger
  PRIVATE POST /bounty/<id>/investigate → start investigation (SSE)
  PRIVATE GET  /bounty/<id>/progress   → SSE stream
  PRIVATE GET  /bounty/<id>/report     → full intelligence report
  PRIVATE GET  /bounty/<id>/blockchain → blockchain + wallet detail
  PRIVATE GET  /bounty/<id>/risk       → risk score breakdown
  PRIVATE GET  /bounty/<id>/le         → LE package viewer
  PRIVATE GET  /bounty/<id>/network    → network graph for domain
  PRIVATE POST /bounty/<id>/approve    → approve takedowns
  PRIVATE GET  /bounty/<id>/submission → I4G submission package
"""

import os
import json
import queue
import threading
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, Response, stream_with_context)
from dotenv import load_dotenv

load_dotenv()

from scripts.bounty_parser import parse_bounty, validate_bounty
from scripts.db import (add_bounty, get_all_bounties, get_bounty,
                        update_status, get_investigation,
                        get_wallets_for_domain, get_public_stats,
                        get_graph_for_domain)
from scripts.submission_packager import format_email_body

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "scambusters_v2_dev")
from scripts.db import init_db
init_db()

# SSE progress queues per bounty
progress_queues: dict[str, queue.Queue] = {}


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "2.0"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def public_dashboard():
    stats = get_public_stats()
    private_url = os.getenv("PRIVATE_DASHBOARD_URL", "/dashboard")
    my_username = os.getenv("I4G_USERNAME", "")
    return render_template("public.html",
                           stats=stats,
                           private_url=private_url,
                           my_username=my_username)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_public_stats())


@app.route("/api/graph/full")
def api_graph_full():
    """Return aggregated network graph across all investigated domains."""
    bounties = get_all_bounties()
    all_nodes = {}
    all_edges = []

    for b in bounties:
        if b.get("status") not in ("complete", "approved"):
            continue
        try:
            graph = get_graph_for_domain(b["domain"], depth=1)
            for node in graph.get("nodes", []):
                all_nodes[node["id"]] = node
            all_edges.extend(graph.get("edges", []))
        except Exception:
            continue

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for e in all_edges:
        key = (e["source"], e["target"], e["type"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    return jsonify({
        "nodes": list(all_nodes.values()),
        "links": unique_edges,
    })


@app.route("/api/graph/<domain>")
def api_graph_domain(domain):
    try:
        from scripts.network_graph import get_graph_data
        return jsonify(get_graph_data(domain, depth=2))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/domain/<domain>")
def api_domain(domain):
    """Public API — returns intelligence summary for a domain."""
    bounties = get_all_bounties()
    for b in bounties:
        if b["domain"] == domain:
            inv = get_investigation(b["bounty_id"], domain)
            if inv:
                return jsonify({
                    "domain": domain,
                    "risk_score": inv.get("risk_score"),
                    "risk_level": inv.get("risk_level"),
                    "primary_ip": (inv.get("urlscan") or {}).get("primary_ip"),
                    "registrar": (inv.get("whois") or {}).get("registrar"),
                    "wallets": get_wallets_for_domain(domain),
                })
    return jsonify({"error": "Domain not found"}), 404


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — BOUNTY BOARD
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    bounties = get_all_bounties()
    stats    = get_public_stats()
    return render_template("index.html", bounties=bounties, stats=stats)


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — BOUNTY INTAKE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/intake", methods=["GET", "POST"])
def intake():
    if request.method == "GET":
        return render_template("intake.html")

    raw = request.form.get("raw_paste", "").strip()
    if not raw:
        return render_template("intake.html", error="Paste is empty.")

    parsed = parse_bounty(raw)
    valid, errors = validate_bounty(parsed)

    if not valid:
        return render_template("intake.html",
                               error=f"Parse failed: {'; '.join(errors)}",
                               raw=raw)

    add_bounty(parsed)
    return redirect(url_for("bounty_detail", bounty_id=parsed["bounty_id"]))


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — BOUNTY DETAIL
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>")
def bounty_detail(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Bounty not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    wallets = get_wallets_for_domain(bounty["domain"]) if investigation else []
    return render_template("bounty.html",
                           bounty=bounty,
                           investigation=investigation,
                           wallets=wallets)


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — INVESTIGATION PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/investigate", methods=["POST"])
def start_investigation(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return jsonify({"error": "Not found"}), 404
    if bounty["status"] in ("investigating", "complete", "approved"):
        return jsonify({"error": f"Already {bounty['status']}"}), 400

    q = queue.Queue()
    progress_queues[bounty_id] = q

    def run():
        from agent import run_investigation
        def cb(stage, msg):
            q.put({"stage": stage, "message": msg,
                   "ts": datetime.utcnow().strftime("%H:%M:%S")})
        try:
            run_investigation(bounty, progress_callback=cb)
        except Exception as e:
            q.put({"stage": "error", "message": str(e),
                   "ts": datetime.utcnow().strftime("%H:%M:%S")})
        finally:
            q.put(None)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/bounty/<bounty_id>/progress")
def progress_stream(bounty_id):
    def generate():
        q = progress_queues.get(bounty_id)
        if not q:
            yield 'data: {"stage":"error","message":"No active investigation"}\n\n'
            return
        while True:
            try:
                event = q.get(timeout=30)
                if event is None:
                    yield 'data: {"stage":"done","message":"Complete"}\n\n'
                    break
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield 'data: {"stage":"ping","message":"..."}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — INTELLIGENCE REPORT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/report")
def view_report(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    wallets = get_wallets_for_domain(bounty["domain"])
    return render_template("report.html",
                           bounty=bounty,
                           investigation=investigation,
                           wallets=wallets)


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — BLOCKCHAIN DETAIL
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/blockchain")
def blockchain_detail(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    wallets = get_wallets_for_domain(bounty["domain"])
    blockchain = (investigation or {}).get("blockchain", {})
    return render_template("blockchain.html",
                           bounty=bounty,
                           investigation=investigation,
                           wallets=wallets,
                           blockchain=blockchain)


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — RISK SCORE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/risk")
def risk_detail(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    return render_template("risk.html",
                           bounty=bounty,
                           investigation=investigation)


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — LE PACKAGE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/le")
def le_package(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    le_pkg = (investigation or {}).get("le_package", {})
    return render_template("le_package.html",
                           bounty=bounty,
                           investigation=investigation,
                           le_package=le_pkg)


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — NETWORK GRAPH
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/network")
def network_view(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    return render_template("network.html", bounty=bounty)


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — TAKEDOWN APPROVAL
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/approve", methods=["POST"])
def approve_takedown(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return jsonify({"error": "Not found"}), 404
    update_status(bounty_id, "approved")
    investigation = get_investigation(bounty_id, bounty["domain"])
    return jsonify({
        "status": "approved",
        "registrar_email": (investigation.get("takedown_registrar") or {}).get("email_draft"),
        "hosting_email":   (investigation.get("takedown_hosting") or {}).get("email_draft"),
    })


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE — SUBMISSION PACKAGE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/submission")
def submission_package(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    pkg  = (investigation or {}).get("submission_package", {})
    body = format_email_body(pkg) if pkg else "No package available yet."
    return render_template("submission.html",
                           bounty=bounty,
                           package=pkg,
                           email_body=body)


# ─────────────────────────────────────────────────────────────────────────────
# API — JSON ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/bounties")
def api_bounties():
    return jsonify(get_all_bounties())


@app.route("/api/bounty/<bounty_id>/investigation")
def api_investigation(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return jsonify({"error": "Not found"}), 404
    inv = get_investigation(bounty_id, bounty["domain"])
    return jsonify(inv or {})


@app.route("/api/wallets/<domain>")
def api_wallets(domain):
    return jsonify(get_wallets_for_domain(domain))


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from scripts.db import init_db
    init_db()
    app.run(
        debug=os.getenv("FLASK_DEBUG", "True") == "True",
        port=int(os.getenv("PORT", 5000)),
        threaded=True
    )
