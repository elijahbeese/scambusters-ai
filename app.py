"""
app.py — ScamBusters Agent Review Dashboard
Flask app for human review and takedown approval workflow.
"""

import os
import json
import glob
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

from scripts.takedown_drafter import draft_all_takedowns

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_key_change_this")

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs/")


def get_all_runs():
    """Return list of all investigation run directories."""
    runs = sorted(glob.glob(os.path.join(OUTPUT_DIR, "run_*")), reverse=True)
    return runs


def load_run_summary(run_dir: str) -> list:
    """Load all domain JSON files from a run directory."""
    summary_file = os.path.join(run_dir, "summary.json")
    if os.path.exists(summary_file):
        with open(summary_file) as f:
            return json.load(f)

    # Fallback: load individual files
    results = []
    for f in glob.glob(os.path.join(run_dir, "*.json")):
        if "summary" not in f:
            with open(f) as fh:
                results.append(json.load(fh))
    return results


@app.route("/")
def index():
    runs = get_all_runs()
    run_names = [os.path.basename(r) for r in runs]
    return render_template("index.html", runs=run_names)


@app.route("/run/<run_name>")
def view_run(run_name):
    run_dir = os.path.join(OUTPUT_DIR, run_name)
    domains = load_run_summary(run_dir)
    return render_template("run.html", run_name=run_name, domains=domains)


@app.route("/domain/<run_name>/<domain_name>")
def view_domain(run_name, domain_name):
    run_dir = os.path.join(OUTPUT_DIR, run_name)
    domain_file = os.path.join(run_dir, f"{domain_name}.json")

    if not os.path.exists(domain_file):
        return "Domain report not found", 404

    with open(domain_file) as f:
        data = json.load(f)

    return render_template("domain.html", data=data, run_name=run_name)


@app.route("/approve/<run_name>/<domain_name>", methods=["POST"])
def approve_takedown(run_name, domain_name):
    """Human approves takedown — generate draft emails."""
    run_dir = os.path.join(OUTPUT_DIR, run_name)
    domain_file = os.path.join(run_dir, f"{domain_name}.json")

    with open(domain_file) as f:
        scam_data = json.load(f)

    takedowns = draft_all_takedowns(scam_data)

    # Save takedown drafts back to the domain file
    scam_data["takedowns"] = takedowns
    scam_data["approved"] = True
    with open(domain_file, "w") as f:
        json.dump(scam_data, f, indent=2, default=str)

    return jsonify(takedowns)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "True") == "True", port=5000)
