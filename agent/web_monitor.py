"""
BRAHMASTRA EDR — web attack detector
Tails web-server access logs and flags SQL injection, XSS,
path traversal, and command injection attempts.
"""
import time, os, re, urllib.parse
import config
from utils import send_alert

SIGNATURES = {
    "SQL Injection": [
        r"union\s+select", r"'?\s+or\s+'?1'?\s*=\s*'?1",
        r";\s*drop\s+table", r"information_schema",
        r"sleep\s*\(", r"benchmark\s*\(", r"'\s*--", r"\bor\b\s+1\s*=\s*1",
    ],
    "XSS": [
        r"<script", r"onerror\s*=", r"onload\s*=",
        r"javascript:", r"alert\s*\(",
    ],
    "Path Traversal": [
        r"\.\./", r"%2e%2e", r"/etc/passwd", r"/etc/shadow",
    ],
    "Command Injection": [
        r";\s*(cat|ls|id|whoami|wget|curl|nc)\b",
        r"\|\s*(bash|sh|nc)\b", r"`.*`",
    ],
}
SEVERITY = {
    "SQL Injection":     ("high", 75),
    "Command Injection": ("high", 80),
    "Path Traversal":    ("medium", 55),
    "XSS":               ("medium", 50),
}
_COMPILED = {atk: [re.compile(p, re.I) for p in pats]
             for atk, pats in SIGNATURES.items()}

def _classify(line):
    decoded = urllib.parse.unquote_plus(line)
    for atk, regexes in _COMPILED.items():
        for rx in regexes:
            if rx.search(decoded):
                return atk, rx.pattern
    return None, None

def _extract_ip(line):
    m = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
    return m.group(1) if m else "unknown"

def run():
    logs = getattr(config, "WEB_LOGS", [])
    handles = []
    while True:
        watched = {p for p, _ in handles}
        for path in logs:
            if path not in watched and os.path.exists(path):
                fh = open(path, "r", errors="ignore")
                fh.seek(0, 2)
                handles.append((path, fh))
        for path, fh in handles:
            for line in fh.readlines():
                atk, pattern = _classify(line)
                if atk:
                    sev, score = SEVERITY[atk]
                    ip = _extract_ip(line)
                    send_alert("web", sev,
                               f"{atk} attempt from {ip}",
                               {"attack_type": atk, "source_ip": ip,
                                "matched_pattern": pattern,
                                "request": line.strip()[:300],
                                "log_file": path}, score)
        time.sleep(2)
