#!/usr/bin/env python3
"""
VMMA Web Application
Flask-based UI for the Vulnerability Management Maturity Assessment.
Replaces the CLI questionnaire with a browser interface.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

# Import assessment data and scoring from existing scripts
sys.path.insert(0, str(Path(__file__).parent))
from maturity_assessment import ASSESSMENT, LEVELS, calculate_domain_score
from generate_report import generate_html, RECOMMENDATIONS

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)

DATA_DIR = Path(__file__).parent


@app.route("/")
def index():
    """Landing page — start new or resume assessment."""
    assessments = sorted(DATA_DIR.glob("assessment_*.json"),
                         key=lambda f: f.stat().st_mtime, reverse=True)
    checkpoints = sorted(DATA_DIR.glob("checkpoint_*.json"),
                         key=lambda f: f.stat().st_mtime, reverse=True)
    return render_template("index.html",
                           assessments=assessments,
                           checkpoints=checkpoints)


@app.route("/new", methods=["POST"])
def new_assessment():
    """Start a new assessment."""
    session["customer"] = {
        "name": request.form.get("name", "").strip(),
        "industry": request.form.get("industry", "").strip(),
        "assessor": request.form.get("assessor", "").strip(),
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    session["completed_domains"] = {}
    session["current_domain_idx"] = 0
    return redirect(url_for("assess"))


@app.route("/resume/<filename>")
def resume(filename):
    """Resume from a checkpoint file."""
    cp_path = DATA_DIR / filename
    if not cp_path.exists():
        return redirect(url_for("index"))
    with open(cp_path) as f:
        cp = json.load(f)
    session["customer"] = cp["customer"]
    session["completed_domains"] = cp.get("completed_domains", {})
    # Find the index of the next incomplete domain
    domains = list(ASSESSMENT.keys())
    idx = 0
    for i, d in enumerate(domains):
        if d not in session["completed_domains"]:
            idx = i
            break
    session["current_domain_idx"] = idx
    return redirect(url_for("assess"))


@app.route("/assess")
def assess():
    """Main assessment page — renders the questionnaire UI."""
    if "customer" not in session:
        return redirect(url_for("index"))
    domains = list(ASSESSMENT.keys())
    return render_template("assess.html",
                           customer=session["customer"],
                           domains=domains,
                           assessment=ASSESSMENT,
                           completed=session.get("completed_domains", {}),
                           current_idx=session.get("current_domain_idx", 0))


@app.route("/api/domains")
def api_domains():
    """Return all domain data as JSON for the frontend."""
    domains = []
    for name, data in ASSESSMENT.items():
        domains.append({
            "name": name,
            "description": data["description"],
            "questions": [{"q": q["q"], "level": q["level"], "weight": q["weight"]}
                          for q in data["questions"]]
        })
    return jsonify(domains)


@app.route("/api/submit", methods=["POST"])
def api_submit():
    """Submit all assessment responses and generate results."""
    payload = request.get_json()
    customer = payload.get("customer", session.get("customer", {}))
    domain_responses = payload.get("domains", {})

    completed_domains = {}
    for domain_name, responses in domain_responses.items():
        # Filter out None entries (unanswered questions)
        clean_responses = [r for r in responses if r is not None and isinstance(r, dict) and r.get("answer")]
        score = calculate_domain_score(clean_responses)
        completed_domains[domain_name] = {
            "score": score,
            "level": LEVELS[score],
            "responses": clean_responses
        }

    scores = [v["score"] for v in completed_domains.values()]
    overall = round(sum(scores) / len(scores), 1) if scores else 1
    overall_level = LEVELS[min(6, max(1, round(overall)))]

    results = {
        "customer": customer,
        "domains": completed_domains,
        "overall_score": overall,
        "overall_level": overall_level
    }

    # Save JSON
    safe_name = customer.get("name", "unknown").replace(" ", "_")
    date = customer.get("date", datetime.now().strftime("%Y-%m-%d"))
    json_file = DATA_DIR / f"assessment_{safe_name}_{date}.json"
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)

    # Generate HTML report
    html = generate_html(results)
    report_file = DATA_DIR / f"assessment_{safe_name}_{date}_report.html"
    with open(report_file, "w") as f:
        f.write(html)

    # Clear session
    session.pop("customer", None)
    session.pop("completed_domains", None)
    session.pop("current_domain_idx", None)

    return jsonify({
        "success": True,
        "json_file": str(json_file.name),
        "report_file": str(report_file.name),
        "results": results
    })


@app.route("/api/report/<filename>")
def api_report(filename):
    """Serve a generated report."""
    report_path = DATA_DIR / filename
    if report_path.exists():
        return report_path.read_text(), 200, {"Content-Type": "text/html"}
    return "Report not found", 404


@app.route("/view/<filename>")
def view_report(filename):
    """View an existing assessment report."""
    json_path = DATA_DIR / filename
    if not json_path.exists():
        return redirect(url_for("index"))
    with open(json_path) as f:
        data = json.load(f)
    html = generate_html(data)
    return html


@app.route("/pdf/<filename>")
def pdf_report(filename):
    """Serve a print-optimized version of the report for PDF download."""
    json_path = DATA_DIR / filename
    if not json_path.exists():
        return redirect(url_for("index"))
    with open(json_path) as f:
        data = json.load(f)
    html = generate_html(data)

    # Inject a print-friendly wrapper and auto-print script
    print_script = """
<style>
@media print {
  body { background: #fff !important; color: #000 !important; padding: 16px !important; }
  .card { border: 1px solid #ccc !important; background: #fff !important; }
  h1, h2, h3 { color: #111 !important; }
  p, li, td, th, span { color: #333 !important; }
  svg text { fill: #333 !important; }
  polygon[fill="#3b82f6"] { fill: #3b82f6 !important; fill-opacity: 0.4 !important; }
  polygon[stroke="#3b82f6"] { stroke: #3b82f6 !important; }
}
</style>
<script>
window.onload = function() {
  setTimeout(function() { window.print(); }, 500);
};
</script>
"""
    # Insert before closing </body>
    html = html.replace("</body>", print_script + "</body>")
    return html


if __name__ == "__main__":
    print("Starting VMMA Web Application...")
    print("Open http://localhost:5050 in your browser")
    app.run(host="0.0.0.0", port=5050, debug=True)
