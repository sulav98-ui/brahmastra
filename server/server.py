#!/usr/bin/env python3
"""
BRAHMASTRA EDR — central server
Receives alerts, AI-triages them, stores them, drives the response
queue, generates AI incident reports, and serves the dashboard.
"""
import json, time
from flask import Flask, request, jsonify, render_template
import db
import ollama_analyst

EXPECTED_TOKEN = "brahmastra-demo-token"
app = Flask(__name__)

def _agent_ok(req):
    tok = req.headers.get("X-Brahmastra-Token")
    return tok is None or tok == EXPECTED_TOKEN

@app.route("/alert", methods=["POST"])
def alert():
    if not _agent_ok(request):
        return jsonify({"error": "bad token"}), 401
    data = request.get_json(force=True)
    ai = ollama_analyst.analyze(data)
    db.add_alert((
        data.get("ts", time.time()), data.get("host", "?"),
        data.get("category", "?"), data.get("severity", "medium"),
        data.get("detail", ""), json.dumps(data.get("raw", {})),
        data.get("score", 0),
        ai["severity"], ai["verdict"], ai["mitre"], ai["action"],
        1 if ai["ai"] else 0,
    ))
    print(f"[ALERT] {data.get('host')} {data.get('category')} "
          f"-> AI:{ai['severity']} {ai['verdict'][:60]}")
    return jsonify({"status": "received", "ai": ai})

@app.route("/api/pending_actions")
def pending_actions():
    if not _agent_ok(request):
        return jsonify({"error": "bad token"}), 401
    return jsonify({"actions": db.pending_actions(request.args.get("host", ""))})

@app.route("/action_result", methods=["POST"])
def action_result():
    if not _agent_ok(request):
        return jsonify({"error": "bad token"}), 401
    d = request.get_json(force=True)
    if d.get("id"):
        db.update_action(d["id"], d.get("status", "done"), d.get("result", ""))
    else:
        db.log_action(d.get("host", "?"), d.get("action", "?"),
                      d.get("target", ""), d.get("status", "done"),
                      d.get("result", ""))
    return jsonify({"ok": True})

@app.route("/action", methods=["POST"])
def action():
    d = request.get_json(force=True)
    aid = db.queue_action(d["host"], d["action"], d.get("target", ""))
    print(f"[ACTION QUEUED] {d['action']} {d.get('target','')} on {d['host']} (id {aid})")
    return jsonify({"queued": aid})

@app.route("/api/alerts")
def api_alerts():
    return jsonify(db.alerts(
        limit=int(request.args.get("limit", 300)),
        host=request.args.get("host"),
        category=request.args.get("category")))

@app.route("/api/stats")
def api_stats():
    return jsonify(db.stats())

@app.route("/api/actions")
def api_actions():
    return jsonify(db.recent_actions())

@app.route("/api/host_report")
def api_host_report():
    host = request.args.get("host", "")
    report = ollama_analyst.incident_report(host, db.alerts(host=host, limit=50))
    return jsonify({"host": host, "report": report})

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    db.init()
    print("=" * 55)
    print("  BRAHMASTRA EDR server -> http://0.0.0.0:5000")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
