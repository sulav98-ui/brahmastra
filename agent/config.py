"""
BRAHMASTRA EDR — agent configuration
Every tunable lives here. Edit this file, not the collectors.
"""
import os

# Project root = the brahmastra/ folder (one level above agent/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- Server ----
SERVER_URL   = os.environ.get("BRAHMASTRA_SERVER", "http://127.0.0.1:5000")
AGENT_TOKEN  = "brahmastra-demo-token"   # shared secret; change for real use
ALERT_TIMEOUT = 30                       # seconds to wait for the server (Ollama can be slow)

# ---- Identity ----
HOSTNAME_OVERRIDE = None    # None = auto-detect the machine name
POLL_INTERVAL     = 3       # base seconds between scan loops

# ---- File integrity monitoring ----
WATCH_PATHS = ["/etc", "/bin", "/usr/bin", "/root/.ssh"]

# ---- Process monitoring ----
SUSPICIOUS_CMDS = [
    "nc -e", "ncat -e", "/dev/tcp/", "bash -i", "python -c 'import socket",
    "wget http", "curl http", "chmod +s", "base64 -d", "nmap", "msfconsole",
    "socat", "/bin/sh -i", "powershell", "certutil",
]

# ---- Web attack detection ----
WEB_LOGS = [
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    os.path.join(PROJECT_ROOT, "test_access.log"),
]

# ---- Malware scanning (YARA + IOC hashes) ----
SCAN_PATHS = ["/tmp", "/dev/shm", os.path.join(PROJECT_ROOT, "scan_intake")]
YARA_RULES = os.path.join(PROJECT_ROOT, "rules", "brahmastra.yar")
IOC_HASHES = os.path.join(PROJECT_ROOT, "rules", "iocs.txt")

# ---- Automated response ----
AUTO_RESPONSE       = True   # let the agent act on its own for extreme risk
AUTO_KILL_THRESHOLD = 90     # auto-kill a process alert scoring >= this
ENABLE_IP_BLOCK     = True   # allow iptables IP blocking (needs root)
QUARANTINE_DIR      = os.path.join(PROJECT_ROOT, "quarantine")
