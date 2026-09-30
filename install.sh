#!/usr/bin/env bash
# BRAHMASTRA EDR - installer (all-in-one manager on this machine)
# Run from inside the repo:  sudo ./install.sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "==============================================="
echo "        BRAHMASTRA EDR  -  installer"
echo "==============================================="

echo "[*] Installing Python dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y python3 python3-pip curl >/dev/null 2>&1 || true
fi
pip install flask requests psutil watchdog 2>/dev/null \
  || pip install flask requests psutil watchdog --break-system-packages 2>/dev/null \
  || pip3 install flask requests psutil watchdog \
  || echo "[!] Install flask/requests/psutil/watchdog manually if this failed."
pip install yara-python 2>/dev/null \
  || pip install yara-python --break-system-packages 2>/dev/null \
  || echo "[i] yara-python optional - hash-based malware detection still works."

if command -v ollama >/dev/null 2>&1; then
    echo "[+] Ollama already installed."
else
    echo "[*] Install Ollama now? (needs internet) [y/N]"
    read -r ans
    if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
        curl -fsSL https://ollama.com/install.sh | sh
    else
        echo "[i] Skipped. Install later from https://ollama.com then: ollama pull llama3.2"
    fi
fi
if command -v ollama >/dev/null 2>&1; then
    echo "[*] Pulling llama3.2 (can take a few minutes)..."
    ollama pull llama3.2 || echo "[!] Run 'ollama pull llama3.2' yourself if this failed."
fi

echo "[*] Installing the 'brahmastra' command..."
cat > /usr/local/bin/brahmastra <<INNER
#!/usr/bin/env bash
ROOT="$ROOT"
case "\$1" in
  server)   cd "\$ROOT/server" && python3 server.py ;;
  agent)    cd "\$ROOT/agent"  && sudo python3 agent.py ;;
  simulate) "\$ROOT/scripts/simulate_attack.sh" ;;
  *) echo "Usage: brahmastra {server|agent|simulate}" ;;
esac
INNER
chmod +x /usr/local/bin/brahmastra

echo ""
echo "  Install complete. Run:"
echo "    ollama serve &"
echo "    brahmastra server"
echo "    brahmastra agent"
echo "  Then open http://<this-ip>:5000   (demo: brahmastra simulate)"
