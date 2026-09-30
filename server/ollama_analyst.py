"""
BRAHMASTRA — Ollama AI analyst
1. analyze()        -> triages a single alert
2. incident_report()-> writes a plain-English incident summary for a host
Runs fully offline against your local Ollama.
"""
import json, requests

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.2"

TRIAGE_PROMPT = """You are Brahmastra, a senior SOC analyst.
You receive ONE security alert from an EDR agent as JSON.
Respond with ONLY a valid JSON object, no extra text, in this exact shape:
{
  "severity": "low|medium|high|critical",
  "verdict": "one short sentence: benign, suspicious, or malicious and why",
  "mitre": "the most relevant MITRE ATT&CK technique ID and name, e.g. 'T1059 Command and Scripting Interpreter', else 'N/A'",
  "action": "one concrete recommended response step"
}
Be decisive. Judge by real attacker behavior, not just keywords.
For a bash/nc reverse shell use T1059. For new users/cron use T1053 or T1136.
For SQL injection use T1190. For file tampering in /etc or /root/.ssh use T1098 or T1547."""

def analyze(alert: dict) -> dict:
    prompt = f"{TRIAGE_PROMPT}\n\nALERT:\n{json.dumps(alert, indent=2)}\n\nJSON response:"
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": MODEL, "prompt": prompt, "stream": False,
            "format": "json", "options": {"temperature": 0.2},
        }, timeout=60)
        r.raise_for_status()
        data = json.loads(r.json().get("response", "").strip())
        return {
            "severity": data.get("severity", alert.get("severity", "medium")),
            "verdict":  data.get("verdict", "No verdict returned."),
            "mitre":    data.get("mitre", "N/A"),
            "action":   data.get("action", "Review manually."),
            "ai": True,
        }
    except Exception as e:
        return {
            "severity": alert.get("severity", "medium"),
            "verdict":  f"AI analyst unavailable ({type(e).__name__}); using agent score.",
            "mitre":    "N/A",
            "action":   "Start Ollama and re-run for AI triage.",
            "ai": False,
        }

def incident_report(host: str, alerts: list) -> str:
    if not alerts:
        return f"No recent alerts for {host}."
    slim = [{"time": a.get("ts"), "category": a.get("category"),
             "severity": a.get("ai_severity") or a.get("severity"),
             "detail": a.get("detail"), "score": a.get("score")}
            for a in alerts[:40]]
    prompt = f"""You are Brahmastra, a senior SOC analyst writing an incident report.
Host: {host}
Below are recent EDR alerts (newest first) as JSON.
Write a concise incident report in plain text with these sections:
SUMMARY: 2-3 sentences on what is happening on this host.
TIMELINE: the key events in order.
ASSESSMENT: overall risk (low/medium/high/critical) and why.
RECOMMENDATIONS: 3-5 concrete next steps.
Be specific and reference the actual alerts. Do not invent details.

ALERTS:
{json.dumps(slim, indent=2)}

INCIDENT REPORT:"""
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": MODEL, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.3},
        }, timeout=120)
        r.raise_for_status()
        return r.json().get("response", "").strip() or "No report generated."
    except Exception as e:
        return f"AI report unavailable: {type(e).__name__}. Is Ollama running?"
