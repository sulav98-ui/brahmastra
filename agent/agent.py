#!/usr/bin/env python3
"""
BRAHMASTRA EDR — endpoint agent (orchestrator)
Runs six detection engines + auto-response + the server-driven
response queue, all as background threads.
"""
import time, os, subprocess, hashlib, threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import config
from utils import send_alert, get, post, HOST
import responder
import web_monitor
import malware_monitor

BANNER = r"""
  ____            _                     _
 | __ ) _ __ __ _| |__  _ __ ___   __ _| |_ _ __ __ _
 |  _ \| '__/ _` | '_ \| '_ ` _ \ / _` | __| '__/ _` |
 | |_) | | | (_| | | | | | | | | | (_| | |_| | | (_| |
 |____/|_|  \__,_|_| |_|_| |_| |_|\__,_|\__|_|  \__,_|
     A I - P O W E R E D   E D R   ·   llama3.2
"""

_seen_pids  = set()
_seen_conns = set()
_file_hashes = {}

def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return None

def _proc_tree(proc, depth=4):
    chain, p = [], proc
    for _ in range(depth):
        try:
            chain.append({"pid": p.pid, "name": p.name(),
                          "cmd": " ".join(p.cmdline()[:6])})
            p = p.parent()
            if p is None:
                break
        except Exception:
            break
    return chain

def process_monitor():
    while True:
        for p in psutil.process_iter(["pid", "name", "cmdline", "username", "ppid"]):
            try:
                pid = p.info["pid"]
                if pid in _seen_pids:
                    continue
                _seen_pids.add(pid)
                cmd = " ".join(p.info["cmdline"] or [])
                if not cmd:
                    continue
                score, reasons = 0, []
                for bad in config.SUSPICIOUS_CMDS:
                    if bad in cmd:
                        score += 40; reasons.append(f"pattern '{bad}'")
                if "/dev/tcp/" in cmd or "bash -i" in cmd or "nc -e" in cmd:
                    score += 55; reasons.append("reverse-shell signature")
                try:
                    parent = psutil.Process(p.info["ppid"]).name()
                    if (p.info["name"] in ("sh", "bash", "dash")
                            and parent in ("nginx", "apache2", "httpd", "node", "python3")):
                        score += 45; reasons.append(f"shell spawned by {parent}")
                except Exception:
                    parent = "?"
                if p.info["username"] == "root":
                    try:
                        puser = psutil.Process(p.info["ppid"]).username()
                        if puser not in ("root", None):
                            score += 30; reasons.append(f"root proc from {puser}")
                    except Exception:
                        pass
                if score >= 40:
                    sev = ("critical" if score >= 90 else
                           "high" if score >= 70 else "medium")
                    try:
                        tree = _proc_tree(psutil.Process(pid))
                    except Exception:
                        tree = []
                    send_alert("process", sev,
                               f"{p.info['name']}: {', '.join(reasons)} | {cmd[:80]}",
                               {"pid": pid, "user": p.info["username"], "parent": parent,
                                "cmd": cmd, "reasons": reasons, "process_tree": tree}, score)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        _seen_pids.intersection_update({p.pid for p in psutil.process_iter()})
        time.sleep(config.POLL_INTERVAL)

class _FileWatcher(FileSystemEventHandler):
    def _report(self, action, path):
        if os.path.isdir(path):
            return
        critical = "/.ssh" in path or path.endswith(("passwd", "shadow", "sudoers"))
        sev = "high" if critical else "medium"
        score = 65 if critical else 30
        newh = _sha256(path) if action != "deleted" else None
        oldh = _file_hashes.get(path)
        _file_hashes[path] = newh
        send_alert("file", sev, f"File {action}: {path}",
                   {"action": action, "path": path,
                    "old_hash": oldh, "new_hash": newh,
                    "critical_path": critical}, score)
    def on_created(self, e):  self._report("created",  e.src_path)
    def on_modified(self, e): self._report("modified", e.src_path)
    def on_deleted(self, e):  self._report("deleted",  e.src_path)
    def on_moved(self, e):    self._report("moved",    e.dest_path)

def file_monitor():
    obs, h = Observer(), _FileWatcher()
    for path in config.WATCH_PATHS:
        if os.path.exists(path):
            try:
                obs.schedule(h, path, recursive=True)
            except Exception:
                pass
    obs.start()
    while True:
        time.sleep(5)

def network_monitor():
    while True:
        for c in psutil.net_connections(kind="inet"):
            try:
                if c.status == "LISTEN" and c.laddr:
                    key = ("LISTEN", c.laddr.port)
                    if key not in _seen_conns:
                        _seen_conns.add(key)
                        send_alert("network", "medium",
                                   f"New listening port {c.laddr.port}",
                                   {"port": c.laddr.port, "pid": c.pid}, 25)
                elif c.status == "ESTABLISHED" and c.raddr:
                    key = ("OUT", c.raddr.ip, c.raddr.port)
                    if key not in _seen_conns:
                        _seen_conns.add(key)
                        ip = c.raddr.ip
                        if not ip.startswith(("10.", "192.168.", "127.", "172.")):
                            send_alert("network", "medium",
                                       f"Outbound to {ip}:{c.raddr.port}",
                                       {"remote": ip, "port": c.raddr.port,
                                        "pid": c.pid}, 35)
            except Exception:
                continue
        time.sleep(config.POLL_INTERVAL)

def _cron_snapshot():
    try:
        return subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    except Exception:
        return ""

def persistence_monitor():
    authlog = "/var/log/auth.log"
    last_cron = _cron_snapshot()
    f = None
    if os.path.exists(authlog):
        f = open(authlog, "r"); f.seek(0, 2)
    while True:
        if f:
            for line in f.readlines():
                if "Failed password" in line:
                    send_alert("login", "medium", "SSH failed login",
                               {"line": line.strip()}, 30)
                elif "useradd" in line or "new user" in line:
                    send_alert("persistence", "high", "New user created",
                               {"line": line.strip()}, 65)
                elif "Accepted" in line:
                    send_alert("login", "low", "SSH login accepted",
                               {"line": line.strip()}, 10)
                elif "sudo:" in line and "COMMAND=" in line:
                    send_alert("privilege", "medium", "sudo command used",
                               {"line": line.strip()}, 25)
        cur = _cron_snapshot()
        if cur != last_cron:
            send_alert("persistence", "high", "Crontab changed",
                       {"before": last_cron, "after": cur}, 70)
            last_cron = cur
        time.sleep(config.POLL_INTERVAL)

def action_poller():
    while True:
        data = get("/api/pending_actions", params={"host": HOST})
        if data and data.get("actions"):
            for act in data["actions"]:
                ok, msg = responder.execute(act["action"], act.get("target", ""))
                post("/action_result", {"id": act["id"], "host": HOST,
                     "action": act["action"], "target": act.get("target", ""),
                     "status": "done" if ok else "failed", "result": msg})
                print(f"[RESPONSE] {act['action']} {act.get('target','')} -> {msg}")
        time.sleep(3)

if __name__ == "__main__":
    print(BANNER)
    print(f"[+] Host: {HOST}  ->  {config.SERVER_URL}")
    print(f"[+] Auto-response: {'ON' if config.AUTO_RESPONSE else 'OFF'} "
          f"(auto-kill score >= {config.AUTO_KILL_THRESHOLD})\n")
    engines = [process_monitor, file_monitor, network_monitor, persistence_monitor,
               web_monitor.run, malware_monitor.run, action_poller]
    for fn in engines:
        threading.Thread(target=fn, daemon=True).start()
    print(f"[+] {len(engines)} engines running. Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Brahmastra agent stopped")
