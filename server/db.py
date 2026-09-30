"""
BRAHMASTRA EDR — database layer (SQLite)
Stores alerts and the response-action queue. Thread-safe via a lock.
"""
import sqlite3, threading, os, time

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brahmastra.db")
_lock = threading.Lock()

def _con():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    c = _con()
    c.execute("""CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, host TEXT, category TEXT, severity TEXT,
        detail TEXT, raw TEXT, score INTEGER,
        ai_severity TEXT, ai_verdict TEXT, ai_mitre TEXT,
        ai_action TEXT, ai_used INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS actions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, host TEXT, action TEXT, target TEXT,
        status TEXT, result TEXT)""")
    c.commit(); c.close()

def add_alert(row):
    with _lock:
        c = _con()
        c.execute("""INSERT INTO alerts(ts,host,category,severity,detail,raw,score,
            ai_severity,ai_verdict,ai_mitre,ai_action,ai_used)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", row)
        c.commit(); c.close()

def alerts(limit=300, host=None, category=None):
    c = _con()
    q = "SELECT * FROM alerts"; cond = []; args = []
    if host:     cond.append("host=?");     args.append(host)
    if category: cond.append("category=?"); args.append(category)
    if cond: q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY id DESC LIMIT ?"; args.append(limit)
    rows = [dict(r) for r in c.execute(q, args).fetchall()]
    c.close(); return rows

def stats():
    c = _con()
    total  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    by_sev = dict(c.execute("SELECT ai_severity,COUNT(*) FROM alerts GROUP BY ai_severity").fetchall())
    by_host= dict(c.execute("SELECT host,COUNT(*) FROM alerts GROUP BY host").fetchall())
    by_cat = dict(c.execute("SELECT category,COUNT(*) FROM alerts GROUP BY category").fetchall())
    c.close()
    return {"total": total, "by_severity": by_sev,
            "by_host": by_host, "by_category": by_cat}

def queue_action(host, action, target):
    with _lock:
        c = _con()
        cur = c.execute("""INSERT INTO actions(ts,host,action,target,status,result)
            VALUES(?,?,?,?,?,?)""", (time.time(), host, action, target, "pending", ""))
        c.commit(); aid = cur.lastrowid; c.close(); return aid

def pending_actions(host):
    with _lock:
        c = _con()
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM actions WHERE host=? AND status='pending'", (host,)).fetchall()]
        for r in rows:
            c.execute("UPDATE actions SET status='sent' WHERE id=?", (r["id"],))
        c.commit(); c.close(); return rows

def update_action(aid, status, result):
    with _lock:
        c = _con()
        c.execute("UPDATE actions SET status=?,result=? WHERE id=?", (status, result, aid))
        c.commit(); c.close()

def log_action(host, action, target, status, result):
    with _lock:
        c = _con()
        c.execute("""INSERT INTO actions(ts,host,action,target,status,result)
            VALUES(?,?,?,?,?,?)""", (time.time(), host, action, target, status, result))
        c.commit(); c.close()

def recent_actions(limit=100):
    c = _con()
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
    c.close(); return rows
