"""
BRAHMASTRA EDR — shared agent utilities.
Ships telemetry to the server and runs local auto-response.
All collectors import send_alert() from here.
"""
import time, socket, requests
import config

HOST = config.HOSTNAME_OVERRIDE or socket.gethostname()
_session = requests.Session()
_headers = {"X-Brahmastra-Token": config.AGENT_TOKEN}

def post(path, payload):
    try:
        r = _session.post(config.SERVER_URL + path, json=payload,
                          headers=_headers, timeout=config.ALERT_TIMEOUT)
        return r.json()
    except Exception as e:
        print(f"[!] server unreachable ({path}): {e}")
        return None

def get(path, params=None):
    try:
        r = _session.get(config.SERVER_URL + path, params=params,
                         headers=_headers, timeout=10)
        return r.json()
    except Exception:
        return None

def send_alert(category, severity, detail, raw, score=0):
    """Ship one alert to the server, then auto-respond if it's extreme."""
    payload = {"host": HOST, "category": category, "severity": severity,
               "detail": detail, "raw": raw, "score": score, "ts": time.time()}
    print(f"[{severity.upper():8}] {category:11} {detail[:70]}")
    resp = post("/alert", payload)
    if (config.AUTO_RESPONSE and category == "process"
            and score >= config.AUTO_KILL_THRESHOLD):
        pid = raw.get("pid")
        if pid:
            import responder
            ok, msg = responder.kill_process(pid)
            print(f"[AUTO-RESPONSE] pid {pid}: {msg}")
            post("/action_result", {"host": HOST, "action": "auto-kill",
                                    "target": str(pid),
                                    "status": "done" if ok else "failed",
                                    "result": msg})
    return resp
