#!/usr/bin/env bash
# BRAHMASTRA EDR - agent installer for a new endpoint
# Usage: sudo ./scripts/install_agent.sh <MANAGER_IP> [hostname]
set -e
MANAGER="${1:?Usage: sudo ./scripts/install_agent.sh <MANAGER_IP> [hostname]}"
HOSTLABEL="${2:-$(hostname)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "[*] Brahmastra agent -> http://$MANAGER:5000 as '$HOSTLABEL'"

echo "[*] Installing dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y python3-pip curl >/dev/null 2>&1 || true
fi
pip install psutil watchdog requests 2>/dev/null \
  || pip install psutil watchdog requests --break-system-packages 2>/dev/null \
  || pip3 install psutil watchdog requests || true

echo "[*] Configuring agent..."
python3 - "$ROOT/agent/config.py" "$MANAGER" "$HOSTLABEL" <<'PY'
import sys, re
cfg, manager, host = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(cfg).read()
s = re.sub(r'("BRAHMASTRA_SERVER",\s*")http://[^"]+(")', r'\1http://%s:5000\2' % manager, s)
s = re.sub(r'HOSTNAME_OVERRIDE\s*=\s*None', 'HOSTNAME_OVERRIDE = "%s"' % host, s)
open(cfg, "w").write(s)
print("    config.py updated")
PY

echo "[*] Testing manager connection..."
curl -s --max-time 5 "http://$MANAGER:5000/api/stats" >/dev/null \
  && echo "[+] Manager reachable." \
  || echo "[!] Cannot reach http://$MANAGER:5000 - check the server and network."
echo "[+] Done. Start with:  cd $ROOT/agent && sudo python3 agent.py"
