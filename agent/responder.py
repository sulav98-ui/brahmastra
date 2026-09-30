"""
BRAHMASTRA EDR — response engine
The actions that contain a threat. Every function returns (ok, message)
and never raises, so the agent keeps running no matter what.
"""
import os, shutil, subprocess, time, hashlib
import config

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def kill_process(pid):
    """Terminate a process by PID (SIGKILL)."""
    try:
        os.kill(int(pid), 9)
        return True, f"SIGKILL sent to PID {pid}"
    except Exception as e:
        return False, f"kill failed: {e}"

def quarantine_file(path):
    """Move a file into the quarantine vault and strip its permissions."""
    try:
        if not os.path.exists(path):
            return False, "file not found"
        os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
        digest = _sha256(path)
        dest = os.path.join(
            config.QUARANTINE_DIR,
            f"{int(time.time())}_{os.path.basename(path)}.quarantine")
        shutil.move(path, dest)
        os.chmod(dest, 0o000)   # no one can execute/read it now
        return True, f"quarantined to {dest} (sha256 {digest[:16]}...)"
    except Exception as e:
        return False, f"quarantine failed: {e}"

def block_ip(ip):
    """Drop all traffic to/from an IP with iptables (needs root)."""
    if not config.ENABLE_IP_BLOCK:
        return False, "IP blocking disabled in config"
    try:
        subprocess.run(["iptables", "-A", "INPUT",  "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
        return True, f"iptables DROP added for {ip}"
    except Exception as e:
        return False, f"block failed: {e}"

def isolate_host():
    """Network-isolate this host: drop everything except loopback."""
    try:
        subprocess.run(["iptables", "-P", "INPUT",  "DROP"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "INPUT",  "-i", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
        return True, "host isolated (loopback only)"
    except Exception as e:
        return False, f"isolate failed: {e}"

def unisolate_host():
    """Lift isolation and flush the firewall rules."""
    try:
        subprocess.run(["iptables", "-P", "INPUT",  "ACCEPT"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-F"], check=True)
        return True, "isolation lifted, firewall flushed"
    except Exception as e:
        return False, f"unisolate failed: {e}"

def execute(action, target=""):
    """Dispatch a named action. Used by the server-driven response queue."""
    a = (action or "").lower()
    if a in ("kill", "kill-process", "auto-kill"): return kill_process(target)
    if a in ("quarantine", "quarantine-file"):     return quarantine_file(target)
    if a in ("block-ip", "block"):                 return block_ip(target)
    if a == "isolate":                             return isolate_host()
    if a == "unisolate":                           return unisolate_host()
    return False, f"unknown action: {action}"

# Safe self-test (no destructive actions):  python3 responder.py
if __name__ == "__main__":
    print("[*] Testing quarantine on a throwaway file...")
    test = "/tmp/brahmastra_responder_test.txt"
    open(test, "w").write("harmless test file")
    print("   ", quarantine_file(test))
    print("[*] Testing unknown action handling...")
    print("   ", execute("frobnicate", "x"))
    print("[+] Responder OK")
