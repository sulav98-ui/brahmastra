# Brahmastra EDR

**The weapon that never misses.** An open-source, AI-powered Endpoint Detection & Response (EDR) platform for Linux, with a local LLM analyst (Ollama / llama3.2), six detection engines, automated + manual response, and a live web dashboard.

## Features

- Six detection engines: process, file integrity, network, persistence/login, web attacks, malware
- AI analyst: every alert triaged by a local llama3.2 (severity, verdict, MITRE mapping, action)
- Response: kill process, quarantine file, block IP, isolate host
- Live themed dashboard with filtering, search, and alert drill-down
- Manager/agent architecture: one central manager, lightweight agents on every endpoint
- 100% offline AI: no API keys, no cloud

## Quick start

    git clone https://github.com/sulav98-ui/brahmastra.git
    cd brahmastra
    sudo ./install.sh
    ollama serve &
    brahmastra server
    brahmastra agent

Open the dashboard at http://<your-ip>:5000 and run a demo: brahmastra simulate

## Detection engines

| Engine | Detects |
|--------|---------|
| Process | reverse shells, suspicious commands, privilege escalation |
| File integrity | changes in /etc, /bin, /usr/bin, /root/.ssh |
| Network | new listening ports, suspicious outbound connections |
| Persistence/login | SSH failures, new users, sudo, crontab changes |
| Web attacks | SQL injection, XSS, path traversal, command injection |
| Malware | known-bad SHA-256 (IOC) + YARA rules |

## Response

Kill process, quarantine file, block IP, isolate host — from the dashboard, or automatically for extreme-risk process alerts.

## License

MIT — fork it, change it, ship it.
