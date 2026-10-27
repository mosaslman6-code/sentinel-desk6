#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SentinelDesk - Cybersecurity Incident Management System (backend)

* Python 3.8+ standard library only - no pip install needed.
* Database: SQLite (file: incidents.db, created automatically on first run).
* Serves the web interface (index.html) and a JSON API from one process.
"""
import platform, base64, csv, hashlib, hmac, io, ipaddress, json, os, random, re, secrets, sqlite3, struct, subprocess, sys, threading, time, webbrowser, smtplib, ssl
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

START_TIME = time.time()
GENESIS = "0" * 64                      # starting value of the tamper-evident audit chain
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

BASE = os.path.dirname(os.path.abspath(__file__))
VERSION = "3.3.0"
DB = os.environ.get("SENTINEL_DB") or os.path.join(BASE, "incidents.db")
DATA_DIR = os.path.dirname(os.path.abspath(DB))
STATIC_DIR = os.path.join(BASE, "static")
EVIDENCE_DIR = os.path.join(DATA_DIR, "evidence")
HOST = os.environ.get("HOST", "127.0.0.1")
TLS_CERT, TLS_KEY = os.environ.get("SENTINEL_TLS_CERT", ""), os.environ.get("SENTINEL_TLS_KEY", "")
TLS_ON = bool(TLS_CERT and TLS_KEY)
PORT = int(os.environ.get("PORT", "8000"))

CATEGORIES = ["Malware", "Phishing", "DDoS", "Unauthorized Access", "Data Leak",
              "Insider Threat", "Vulnerability Exploit", "Policy Violation", "Other"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
STATUSES = ["New", "Investigating", "Contained", "Resolved", "Closed"]
OPEN_STATUSES = ("New", "Investigating", "Contained")
SOURCES = ["SIEM alert", "EDR alert", "User report", "Email gateway", "Firewall / IDS",
           "Threat intel", "Audit / review", "Other"]
SLA_HOURS = {"Critical": 4, "High": 8, "Medium": 24, "Low": 72}
ROLES = ("admin", "analyst", "viewer")
ACTION_TYPES = ["Analysis", "Containment", "Eradication", "Recovery", "Communication", "Other"]
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
BACKUP_RE = re.compile(r"^incidents-\d{8}-\d{6}-(auto|manual|prerestore)\.db$")
LOOKUP_KINDS = {"category": ("Incident types", "incidents", "category"),
                "source": ("Detection sources", "incidents", "source"),
                "action_type": ("Action types", "events", "tag")}
EVENT_KINDS = ["created", "comment", "note", "status", "assign", "severity", "close", "evidence", "ioc", "check", "classify", "edit"]
DATE_COLS = {"created_at", "updated_at", "due_at", "resolved_at", "closed_at", "at", "last_login"}
TABLES = {  # tables exposed in the Database manager
    "incidents": {"pk": "id"},
    "mentions": {"pk": "id", "readonly": True},
    "api_tokens": {"pk": "id", "readonly": True, "hidden": ["token_hash"]},
    "assets": {"pk": "id"},
    "events": {"pk": "id"},
    "users": {"pk": "id", "hidden": ["salt", "pw_hash", "totp_secret"]},
    "lookups": {"pk": "id"},
    "settings": {"pk": "key", "no_insert": True, "no_delete": True},
    "audit": {"pk": "id", "readonly": True},
    "notification_log": {"pk": "id", "readonly": True},
    "iocs": {"pk": "id", "readonly": True},
    "evidence": {"pk": "id", "readonly": True, "hidden": ["stored_name"]},
    "checklist": {"pk": "id", "readonly": True},
}

TLP = ["WHITE", "GREEN", "AMBER", "RED"]
MITRE = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
         "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
         "Collection", "Command and Control", "Exfiltration", "Impact"]
IOC_TYPES = ["ip", "domain", "url", "hash", "email", "file", "other"]
EVIDENCE_MAX = 8 * 1024 * 1024          # 8 MB per file
JSON_LIMIT, UPLOAD_LIMIT = 1_000_000, 12 * 1024 * 1024
DEFAULT_PASSWORDS = {"admin": "Admin@123", "analyst": "Analyst@123", "sara": "Analyst@123", "viewer": "Viewer@123"}

# Response playbooks: a checklist is created for every new incident from its category (English, Arabic).
PLAYBOOKS = {
    "Malware": [
        ("Isolate the affected host from the network", "عزل الجهاز المصاب عن الشبكة"),
        ("Capture memory and disk evidence before cleaning", "التقاط صورة الذاكرة والقرص قبل التنظيف"),
        ("Identify the malware family and collect IOCs", "تحديد عائلة البرمجية الخبيثة وجمع مؤشرات الاختراق"),
        ("Block the IOCs on firewall, proxy and EDR", "حظر المؤشرات على الجدار الناري والبروكسي وEDR"),
        ("Remove the malware and reset affected credentials", "إزالة البرمجية الخبيثة وإعادة تعيين بيانات الدخول المتأثرة"),
        ("Restore from a clean backup and verify", "الاستعادة من نسخة احتياطية سليمة والتحقق منها"),
        ("Notify the asset owner and record lessons learned", "إبلاغ مالك الأصل وتوثيق الدروس المستفادة")],
    "Phishing": [
        ("Collect the original email with full headers", "جمع الرسالة الأصلية مع الترويسات الكاملة"),
        ("Identify all recipients and who clicked or entered credentials", "تحديد كل المستلمين ومن نقر أو أدخل بياناته"),
        ("Purge the message from all mailboxes", "حذف الرسالة من جميع صناديق البريد"),
        ("Block the sender domain and malicious URLs", "حظر نطاق المرسل والروابط الخبيثة"),
        ("Reset passwords and revoke sessions for affected users", "إعادة تعيين كلمات المرور وإنهاء جلسات المستخدمين المتأثرين"),
        ("Warn staff and report to the awareness team", "تحذير الموظفين وإبلاغ فريق التوعية")],
    "DDoS": [
        ("Confirm the attack and capture the traffic profile", "تأكيد الهجوم وتوثيق نمط الحركة"),
        ("Enable rate limiting or upstream scrubbing", "تفعيل تحديد المعدل أو التنظيف لدى مزود الخدمة"),
        ("Contact the ISP or CDN provider", "التواصل مع مزود الإنترنت أو الـ CDN"),
        ("Block abusive sources and protocols", "حظر المصادر والبروتوكولات المسيئة"),
        ("Verify service recovery and monitor", "التحقق من عودة الخدمة ومراقبتها"),
        ("Review capacity and resilience gaps", "مراجعة السعة وثغرات المرونة")],
    "Unauthorized Access": [
        ("Confirm the accessed account or system and the time window", "تأكيد الحساب أو النظام المخترق والنافذة الزمنية"),
        ("Disable or reset the compromised accounts", "تعطيل الحسابات المخترقة أو إعادة تعيينها"),
        ("Review logs for lateral movement and persistence", "مراجعة السجلات بحثاً عن حركة جانبية أو بقاء"),
        ("Block the source IP addresses", "حظر عناوين IP المصدر"),
        ("Enforce MFA and review privileges", "فرض المصادقة الثنائية ومراجعة الصلاحيات"),
        ("Document findings and monitoring improvements", "توثيق النتائج وتحسينات المراقبة")],
    "Data Leak": [
        ("Determine the data types and volume exposed", "تحديد أنواع البيانات وحجمها المكشوف"),
        ("Contain the exposure (remove or lock access)", "احتواء التسريب (إزالة الوصول أو إغلاقه)"),
        ("Preserve evidence and access logs", "حفظ الأدلة وسجلات الوصول"),
        ("Assess legal and regulatory notification duties", "تقييم الالتزامات القانونية والتنظيمية للإبلاغ"),
        ("Notify affected parties if required", "إبلاغ الأطراف المتأثرة عند الحاجة"),
        ("Review DLP and access controls", "مراجعة ضوابط منع تسرب البيانات والوصول")],
    "Insider Threat": [
        ("Preserve evidence discreetly", "حفظ الأدلة بسرية"),
        ("Involve HR and Legal", "إشراك الموارد البشرية والشؤون القانونية"),
        ("Restrict access as appropriate", "تقييد الوصول بالقدر المناسب"),
        ("Review the user's recent activity", "مراجعة نشاط المستخدم الأخير"),
        ("Document the outcome and corrective actions", "توثيق النتيجة والإجراءات التصحيحية")],
    "Vulnerability Exploit": [
        ("Identify the vulnerable component and CVE", "تحديد المكوّن الضعيف ورقم CVE"),
        ("Apply the patch or a mitigation", "تطبيق التحديث أو معالجة مؤقتة"),
        ("Scan for other exposed instances", "فحص بقية النسخ المعرضة"),
        ("Hunt for persistence (webshells, new accounts)", "البحث عن آليات البقاء (Webshell، حسابات جديدة)"),
        ("Verify with a follow-up scan", "التحقق بفحص لاحق")],
    "Policy Violation": [
        ("Document the violation and the policy affected", "توثيق المخالفة والسياسة المتأثرة"),
        ("Inform the user's manager", "إبلاغ مدير المستخدم"),
        ("Remediate (remove data or software)", "المعالجة (إزالة البيانات أو البرنامج)"),
        ("Deliver targeted awareness training", "تقديم تدريب توعوي موجّه")],
}
PLAYBOOK_DEFAULT = [
    ("Triage and scope the incident", "الفرز وتحديد نطاق الحادث"),
    ("Contain the threat", "احتواء التهديد"),
    ("Collect and preserve evidence", "جمع الأدلة وحفظها"),
    ("Eradicate and recover", "الاستئصال والاستعادة"),
    ("Communicate with stakeholders", "التواصل مع أصحاب العلاقة"),
    ("Record lessons learned", "توثيق الدروس المستفادة")]

ASSET_TYPES = ["Server", "Workstation", "Laptop", "Network device", "Application", "Database", "Cloud service", "Mobile device", "Other"]
CRITICALITY = ["Low", "Medium", "High", "Critical"]
LEVEL_WEIGHT = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
ASSET_CRIT = {}            # lower-case asset name -> criticality; refreshed on every API request
PAGE_SIZE = 25
SESSION_TTL = 8 * 3600

SESSIONS, FAILS, LAST_TOTP = {}, {}, {}
LOCK = threading.Lock()

# ---------------------------------------------------------------- attack lab (attack_lab/)
# A self-contained, local-only practice target + attack simulator + detector, started on demand
# by an admin (Dashboard > Live attack feed, or POST /api/attack_lab/start). Every process it
# launches talks to 127.0.0.1 only - see attack_lab/README_AR.md.
LAB_DIR = os.path.join(BASE, "attack_lab")
LAB_PROCS = {}


def _lab_alive(name):
    p = LAB_PROCS.get(name)
    return p is not None and p.poll() is None


def attack_lab_status():
    return {"available": os.path.isdir(LAB_DIR), "running": _lab_alive("target") and _lab_alive("detector") and _lab_alive("attacker")}


def start_attack_lab():
    if not os.path.isdir(LAB_DIR):
        return False, "The attack_lab folder was not found next to server.py."
    tok = os.environ.get("SENTINEL_WEBHOOK_TOKEN", "").strip()
    if not tok:
        return False, "SENTINEL_WEBHOOK_TOKEN is not configured."
    env = dict(os.environ)
    env["SENTINEL_URL"] = f"http://127.0.0.1:{PORT}"
    for name, args in (("target", ["target_app.py"]), ("detector", ["detector.py"]), ("attacker", ["attacker.py", "--loop"])):
        if not _lab_alive(name):
            LAB_PROCS[name] = subprocess.Popen([sys.executable, "-u"] + args, cwd=LAB_DIR, env=env,
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)
    return True, "started"


def stop_attack_lab():
    for name, p in list(LAB_PROCS.items()):
        if p and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass


# ---------------------------------------------------------------- helpers
def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse(s):
    return datetime.fromisoformat(s) if s else None


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()


def strong_password(pw):
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


COMMON_PASSWORDS = {"password1", "password123", "passw0rd", "p@ssw0rd", "p@ssword1", "admin123", "admin@123", "analyst@123", "viewer@123",
                    "welcome1", "welcome123", "letmein1", "qwerty123", "qwerty12345", "12345678a", "abc12345", "iloveyou1", "changeme1",
                    "sentinel1", "sentineldesk1", "test1234", "user1234", "password@123", "iraq1234", "basra1234"}
PW_HISTORY = 5


def password_error(c, username, pw):
    """Why a new password is not acceptable (or None): too weak, too common, contains the username, or reused."""
    if not strong_password(pw):
        return "Password needs 8+ characters with letters and numbers"
    low = pw.lower()
    if low in COMMON_PASSWORDS or (len(username) >= 3 and username.lower() in low):
        return "That password is too common or contains the username"
    row = c.execute("SELECT salt,pw_hash FROM users WHERE username=?", (username,)).fetchone()
    old = [(row["salt"], row["pw_hash"])] if row else []
    old += [(r["salt"], r["pw_hash"]) for r in c.execute("SELECT salt,pw_hash FROM pw_history WHERE username=? ORDER BY id DESC LIMIT ?", (username, PW_HISTORY))]
    if any(hmac.compare_digest(hash_pw(pw, salt), h) for salt, h in old):
        return "You cannot reuse one of your last passwords"
    return None


def remember_password(c, username):
    row = c.execute("SELECT salt,pw_hash FROM users WHERE username=?", (username,)).fetchone()
    if row:
        c.execute("INSERT INTO pw_history(username,salt,pw_hash,at) VALUES(?,?,?,?)", (username, row["salt"], row["pw_hash"], iso(utcnow())))
        c.execute("DELETE FROM pw_history WHERE username=? AND id NOT IN (SELECT id FROM pw_history WHERE username=? ORDER BY id DESC LIMIT ?)",
                  (username, username, PW_HISTORY))


def add_user(c, username, full_name, role, pw, email=""):
    salt = secrets.token_hex(16)
    c.execute("INSERT INTO users(username,full_name,email,role,salt,pw_hash,active,created_at) VALUES(?,?,?,?,?,?,1,?)",
              (username, full_name, email, role, salt, hash_pw(pw, salt), iso(utcnow())))


def audit_hash(prev, at, user, action, detail):
    return hashlib.sha256("|".join((prev, at, user, action, detail)).encode("utf-8")).hexdigest()


def audit(c, user, action, detail=""):
    """Append to the audit log. Every entry stores the SHA-256 of its content plus the previous entry's hash (a hash chain),
    so editing or deleting any past entry is detectable with verify_audit()."""
    at, detail = iso(utcnow()), "" if detail is None else str(detail)
    last = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last and last["hash"] else GENESIS
    c.execute("INSERT INTO audit(at,username,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
              (at, user, action, detail, prev, audit_hash(prev, at, user, action, detail)))


def seal_audit(c):
    """Give entries written by older versions a place in the chain (done once, at upgrade time)."""
    prev = GENESIS
    for r in c.execute("SELECT id,at,username,action,detail,hash FROM audit ORDER BY id").fetchall():
        if r["hash"]:
            prev = r["hash"]
            continue
        h = audit_hash(prev, r["at"], r["username"], r["action"], r["detail"] or "")
        c.execute("UPDATE audit SET prev_hash=?, hash=? WHERE id=?", (prev, h, r["id"]))
        prev = h


def verify_audit(c):
    prev, n = GENESIS, 0
    for r in c.execute("SELECT id,at,username,action,detail,prev_hash,hash FROM audit ORDER BY id"):
        n += 1
        if r["prev_hash"] != prev:
            return {"ok": False, "checked": n, "bad_id": r["id"], "reason": "An earlier entry was removed or reordered"}
        if r["hash"] != audit_hash(prev, r["at"], r["username"], r["action"], r["detail"] or ""):
            return {"ok": False, "checked": n, "bad_id": r["id"], "reason": "This entry was modified after it was written"}
        prev = r["hash"]
    return {"ok": True, "checked": n, "bad_id": None, "reason": ""}


def event(c, iid, kind, text, user, at=None, tag=""):
    c.execute("INSERT INTO events(incident_id,kind,tag,text,username,at) VALUES(?,?,?,?,?,?)",
              (iid, kind, tag, text, user, at or iso(utcnow())))


def dn(c, username):
    r = c.execute("SELECT full_name FROM users WHERE username=?", (username,)).fetchone()
    return r["full_name"] if r else username


def touch(c, iid, at=None):
    c.execute("UPDATE incidents SET updated_at=? WHERE id=?", (at or iso(utcnow()), iid))


def init():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
      email TEXT DEFAULT '', role TEXT NOT NULL CHECK(role IN('admin','analyst','viewer')),
      salt TEXT NOT NULL, pw_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, last_login TEXT);
    CREATE TABLE IF NOT EXISTS incidents(
      id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL,
      severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New', asset TEXT NOT NULL, source TEXT NOT NULL,
      assignee TEXT NOT NULL DEFAULT 'Unassigned', reporter TEXT NOT NULL, created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL, due_at TEXT NOT NULL, resolved_at TEXT, closed_at TEXT, resolution TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      kind TEXT NOT NULL, tag TEXT NOT NULL DEFAULT '', text TEXT NOT NULL, username TEXT NOT NULL, at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit(
      id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT);
    CREATE TABLE IF NOT EXISTS lookups(
      id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL CHECK(kind IN('category','source','action_type')),
      name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, sort INTEGER NOT NULL DEFAULT 0, UNIQUE(kind,name));
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS notification_log(
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT NOT NULL UNIQUE,
      channel TEXT NOT NULL, status TEXT NOT NULL, detail TEXT DEFAULT '', sent_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS webhook_events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL, external_id TEXT NOT NULL,
      incident_id TEXT, received_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
      UNIQUE(provider, external_id));
    CREATE TABLE IF NOT EXISTS iocs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      type TEXT NOT NULL, value TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', added_by TEXT NOT NULL, added_at TEXT NOT NULL,
      UNIQUE(incident_id, type, value));
    CREATE TABLE IF NOT EXISTS evidence(
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      filename TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, stored_name TEXT NOT NULL,
      note TEXT NOT NULL DEFAULT '', uploaded_by TEXT NOT NULL, uploaded_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS checklist(
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      text TEXT NOT NULL, text_ar TEXT NOT NULL DEFAULT '', done INTEGER NOT NULL DEFAULT 0,
      done_by TEXT, done_at TEXT, sort INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS assets(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, type TEXT NOT NULL DEFAULT 'Other',
      owner TEXT NOT NULL DEFAULT '', department TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '',
      criticality TEXT NOT NULL DEFAULT 'Medium' CHECK(criticality IN('Low','Medium','High','Critical')),
      notes TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT 'system', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS mentions(
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      username TEXT NOT NULL, by_user TEXT NOT NULL, excerpt TEXT NOT NULL DEFAULT '', at TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS ix_mention_user ON mentions(username, read);
    CREATE TABLE IF NOT EXISTS api_tokens(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, name TEXT NOT NULL, prefix TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE, scope TEXT NOT NULL CHECK(scope IN('read','write')), created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL, last_used TEXT, revoked INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS pw_history(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, salt TEXT NOT NULL, pw_hash TEXT NOT NULL, at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_pwh_user ON pw_history(username, id);
    CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS ix_ioc_inc ON iocs(incident_id);
    CREATE INDEX IF NOT EXISTS ix_ioc_val ON iocs(value);
    CREATE INDEX IF NOT EXISTS ix_evd_inc ON evidence(incident_id);
    CREATE INDEX IF NOT EXISTS ix_chk_inc ON checklist(incident_id);
    CREATE INDEX IF NOT EXISTS ix_audit_at ON audit(at);
    CREATE INDEX IF NOT EXISTS ix_inc_created ON incidents(created_at);
    CREATE INDEX IF NOT EXISTS ix_evt_inc ON events(incident_id);
    CREATE INDEX IF NOT EXISTS ix_inc_source ON incidents(source);
    """)
    if not c.execute("SELECT 1 FROM lookups").fetchone():
        for kind, items in (("category", CATEGORIES), ("source", SOURCES), ("action_type", ACTION_TYPES)):
            for i, name in enumerate(items):
                c.execute("INSERT INTO lookups(kind,name,sort) VALUES(?,?,?)", (kind, name, i))
    for sev, hrs in SLA_HOURS.items():
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", ("sla_" + sev, str(hrs)))
    if "tag" not in [r["name"] for r in c.execute("PRAGMA table_info(events)")]:  # upgrade older databases
        c.execute("ALTER TABLE events ADD COLUMN tag TEXT NOT NULL DEFAULT ''")
    for tbl, col, ddl in (("incidents", "mitre", "TEXT NOT NULL DEFAULT ''"), ("incidents", "tlp", "TEXT NOT NULL DEFAULT 'AMBER'"),
                          ("incidents", "root_cause", "TEXT NOT NULL DEFAULT ''"), ("incidents", "lessons", "TEXT NOT NULL DEFAULT ''"),
                          ("users", "totp_secret", "TEXT NOT NULL DEFAULT ''"), ("users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
                          ("audit", "prev_hash", "TEXT NOT NULL DEFAULT ''"), ("audit", "hash", "TEXT NOT NULL DEFAULT ''")):
        if col not in [r["name"] for r in c.execute(f"PRAGMA table_info({tbl})")]:  # additive upgrade of older databases
            c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {ddl}")
    seal_audit(c)
    if not c.execute("SELECT 1 FROM assets").fetchone():
        sync_assets_from_incidents(c)
    if not c.execute("SELECT 1 FROM users").fetchone():
        add_user(c, "admin", "System Administrator", "admin", "Admin@123", "admin@example.com")
        add_user(c, "analyst", "Alex Morgan", "analyst", "Analyst@123", "alex@example.com")
        add_user(c, "sara", "Sara Khalid", "analyst", "Analyst@123", "sara@example.com")
        add_user(c, "viewer", "Read-only Auditor", "viewer", "Viewer@123", "audit@example.com")
    c.commit()
    c.close()


def guess_asset(name):
    """Best-effort type / criticality for assets discovered in older data; editable afterwards in the inventory."""
    n = name.lower()
    if re.search(r"(^|[^a-z])(dc|ad|active directory)([^a-z]|$)|domain controller", n):
        return "Server", "Critical"
    if re.search(r"database|\bdb\b|crm", n):
        return "Database", "High"
    if re.search(r"srv|server|mail|gateway|vpn|proxy|fw|firewall", n):
        return "Server", "High"
    if re.search(r"laptop", n):
        return "Laptop", "Medium"
    if re.search(r"-pc-|-ws-|\bws\b|\bpc\b|workstation", n):
        return "Workstation", "Medium"
    if re.search(r"wi-?fi|switch|router|network", n):
        return "Network device", "Medium"
    if re.search(r"portal|site|web|app|payments", n):
        return "Application", "High"
    return "Other", "Medium"


def sync_assets_from_incidents(c, user="system"):
    """Create inventory records for every asset name already used by incidents (existing databases upgrade automatically)."""
    for (name,) in c.execute("SELECT DISTINCT asset FROM incidents WHERE TRIM(asset)!=''").fetchall():
        if c.execute("SELECT 1 FROM assets WHERE name=?", (name,)).fetchone():
            continue
        typ, crit = guess_asset(name)
        c.execute("INSERT INTO assets(name,type,criticality,notes,created_by,created_at) VALUES(?,?,?,?,?,?)",
                  (name, typ, crit, "Imported from incidents - please review type and criticality.", user, iso(utcnow())))


def refresh_asset_crit(c):
    ASSET_CRIT.clear()
    for r in c.execute("SELECT name,criticality FROM assets"):
        ASSET_CRIT[r["name"].lower()] = r["criticality"]


def risk_of(severity, asset):
    """Risk score 0-100 = incident severity x criticality of the affected asset (unregistered assets count as Medium)."""
    crit = ASSET_CRIT.get((asset or "").strip().lower(), "Medium")
    score = round(LEVEL_WEIGHT.get(severity, 1) * LEVEL_WEIGHT[crit] / 16 * 100)
    band = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    return score, band, crit


MENTION_RE = re.compile(r"(?<![\w.@-])@([A-Za-z0-9._-]{3,32})")


def find_mentions(c, text, author):
    """Active analysts/admins mentioned as @username (the author is never notified about their own comment)."""
    found = []
    for m in MENTION_RE.finditer(text):
        row = c.execute("SELECT username FROM users WHERE username=? COLLATE NOCASE AND active=1 AND role IN('admin','analyst')",
                        (m.group(1).rstrip(".-_"),)).fetchone()
        if row and row["username"] != author and row["username"] not in found:
            found.append(row["username"])
    return found


def sid_hash(sid):
    return hashlib.sha256(sid.encode()).hexdigest()[:16]


BANDS = ("Critical", "High", "Medium", "Low")


def risk_overview(open_rows):
    bands, per = {b: 0 for b in BANDS}, {}
    for r in open_rows:
        sc, band, crit = risk_of(r["severity"], r["asset"])
        bands[band] += 1
        a = per.setdefault(r["asset"], {"name": r["asset"], "crit": crit, "open": 0, "max": 0, "sum": 0})
        a["open"] += 1
        a["max"], a["sum"] = max(a["max"], sc), a["sum"] + sc
    top = sorted(per.values(), key=lambda x: (-x["max"], -x["sum"], x["name"]))[:5]
    scores = [risk_of(r["severity"], r["asset"])[0] for r in open_rows]
    return {"bands": [{"name": b, "value": bands[b]} for b in BANDS], "top_assets": top,
            "avg": round(sum(scores) / len(scores)) if scores else None}


TOKEN_PREFIX = "sdk_"


def hash_token(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def when_of(sv):
    dt = datetime.fromisoformat(sv.strip().replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def token_auth(c, header):
    """Row of a valid, unexpired, unrevoked API token for an 'Authorization: Bearer sdk_...' header, else None."""
    tok = header[7:].strip()
    if not tok.startswith(TOKEN_PREFIX) or len(tok) > 100:
        return None
    r = c.execute("SELECT * FROM api_tokens WHERE token_hash=? AND revoked=0", (hash_token(tok),)).fetchone()
    if not r or when_of(r["expires_at"]) < utcnow():
        return None
    now = utcnow()
    if not r["last_used"] or (now - when_of(r["last_used"])).total_seconds() > 60:
        c.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (iso(now), r["id"]))
        c.commit()
    return r


def get_lookups(c, kind, active_only=True):
    sql = "SELECT name FROM lookups WHERE kind=?" + (" AND active=1" if active_only else "") + " ORDER BY sort, id"
    return [r["name"] for r in c.execute(sql, (kind,))]


def get_sla(c):
    out = dict(SLA_HOURS)
    for r in c.execute("SELECT key,value FROM settings WHERE key LIKE 'sla_%'"):
        sev = r["key"][4:]
        if sev in out:
            try:
                out[sev] = max(1, int(r["value"]))
            except ValueError:
                pass
    return out


def notification_config():
    """Read notification credentials from environment variables, never from the database."""
    try:
        check_seconds = int(os.environ.get("SENTINEL_SLA_CHECK_SECONDS", "60") or "60")
    except ValueError:
        check_seconds = 60
    return {
        "email_enabled": bool(os.environ.get("SENTINEL_SMTP_HOST") and os.environ.get("SENTINEL_SMTP_FROM") and os.environ.get("SENTINEL_ALERT_EMAILS")),
        "telegram_enabled": bool(os.environ.get("SENTINEL_TELEGRAM_BOT_TOKEN") and os.environ.get("SENTINEL_TELEGRAM_CHAT_ID")),
        "slack_enabled": bool(os.environ.get("SENTINEL_SLACK_WEBHOOK_URL")),
        "discord_enabled": bool(os.environ.get("SENTINEL_DISCORD_WEBHOOK_URL")),
        "email_recipients": [x.strip() for x in os.environ.get("SENTINEL_ALERT_EMAILS", "").split(",") if x.strip()],
        "sla_check_seconds": max(30, check_seconds),
    }


def deliver_notification(subject, message):
    """Send through any configured SMTP, Telegram, Slack, and Discord channels."""
    cfg = notification_config(); results = {}
    if cfg["email_enabled"]:
        try:
            from email.message import EmailMessage
            host = os.environ["SENTINEL_SMTP_HOST"]; port = int(os.environ.get("SENTINEL_SMTP_PORT", "587"))
            user = os.environ.get("SENTINEL_SMTP_USER", ""); password = os.environ.get("SENTINEL_SMTP_PASSWORD", "")
            sender = os.environ["SENTINEL_SMTP_FROM"]; recipients = cfg["email_recipients"]
            msg = EmailMessage(); msg["Subject"] = "[SentinelDesk] " + subject; msg["From"] = sender
            msg["To"] = ", ".join(recipients); msg.set_content(message); context = ssl.create_default_context()
            implicit_ssl = os.environ.get("SENTINEL_SMTP_SSL", "0") == "1"
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=10) if implicit_ssl else smtplib.SMTP(host, port, timeout=10)
            with server:
                server.ehlo()
                if not implicit_ssl and os.environ.get("SENTINEL_SMTP_STARTTLS", "1") != "0": server.starttls(context=context); server.ehlo()
                if user: server.login(user, password)
                server.send_message(msg)
            results["email"] = (True, "sent")
        except Exception as e: results["email"] = (False, str(e)[:250])
    if cfg["telegram_enabled"]:
        try:
            url = os.environ.get("SENTINEL_TELEGRAM_API", "https://api.telegram.org").rstrip("/") + "/bot" + os.environ["SENTINEL_TELEGRAM_BOT_TOKEN"] + "/sendMessage"
            payload = json.dumps({"chat_id": os.environ["SENTINEL_TELEGRAM_CHAT_ID"], "text": "SentinelDesk\n" + subject + "\n\n" + message, "disable_web_page_preview": True}).encode()
            req = Request(url, data=payload, headers={"Content-Type":"application/json"}, method="POST")
            with urlopen(req, timeout=10) as response:
                body = json.loads(response.read(4096).decode())
                if not body.get("ok"): raise RuntimeError("Telegram API rejected message")
            results["telegram"] = (True, "sent")
        except Exception as e: results["telegram"] = (False, str(e)[:250])
    for channel, envkey in (("slack", "SENTINEL_SLACK_WEBHOOK_URL"), ("discord", "SENTINEL_DISCORD_WEBHOOK_URL")):
        hook = os.environ.get(envkey, "").strip()
        if not hook: continue
        try:
            content = ("*SentinelDesk — " + subject + "*\n" + message) if channel == "slack" else ("**SentinelDesk — " + subject + "**\n" + message)[:1900]
            payload = json.dumps({"text": content} if channel == "slack" else {"content": content}).encode()
            req = Request(hook, data=payload, headers={"Content-Type":"application/json"}, method="POST")
            with urlopen(req, timeout=10) as response: response.read(2048)
            results[channel] = (True, "sent")
        except Exception as e: results[channel] = (False, str(e)[:250])
    return results


def notify_once(event_key, subject, message):
    """Deduplicate event notifications and persist delivery results."""
    cfg = notification_config()
    if not any(cfg[k] for k in ("email_enabled", "telegram_enabled", "slack_enabled", "discord_enabled")): return
    c = db()
    try:
        c.execute("INSERT INTO notification_log(event_key,channel,status,detail,sent_at) VALUES(?,?,?,?,?)", (event_key, "all", "pending", "", iso(utcnow())))
        c.commit()
    except sqlite3.IntegrityError:
        c.close(); return
    except Exception:
        c.close(); return
    results = deliver_notification(subject, message)
    summary = "; ".join(f"{k}: {'ok' if v[0] else 'failed'} {v[1]}" for k,v in results.items())
    c.execute("UPDATE notification_log SET status=?,detail=?,sent_at=? WHERE event_key=?", ("sent" if results and all(v[0] for v in results.values()) else "partial_or_failed", summary[:1000], iso(utcnow()), event_key))
    c.commit(); c.close()


def sla_notification_worker():
    """Check open incidents periodically and notify once when their response target is breached."""
    while True:
        try:
            c = db(); rows = c.execute("SELECT id,title,severity,asset,due_at,assignee FROM incidents WHERE status IN('New','Investigating','Contained')").fetchall(); c.close()
            now = utcnow()
            for r in rows:
                try: due = parse(r["due_at"])
                except Exception: continue
                if due and due <= now:
                    message = f"Incident: {r['id']} — {r['title']}\nSeverity: {r['severity']}\nAsset: {r['asset']}\nAssignee: {r['assignee']}\nSLA due: {r['due_at']}\nResponse target exceeded."
                    notify_once("sla-breach:" + r["id"], "SLA target breached", message)
        except Exception as e: print("SLA notification worker error:", repr(e))
        time.sleep(notification_config()["sla_check_seconds"])


def make_backup(tag="manual"):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    name = f"incidents-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{tag}.db"
    while os.path.exists(os.path.join(BACKUP_DIR, name)):      # never overwrite an existing backup
        time.sleep(0.25)
        name = f"incidents-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{tag}.db"
    src, dst = sqlite3.connect(DB), sqlite3.connect(os.path.join(BACKUP_DIR, name))
    with dst:
        src.backup(dst)
    dst.close()
    src.close()
    if tag == "auto":
        for old in sorted(f for f in os.listdir(BACKUP_DIR) if f.endswith("-auto.db"))[:-10]:
            os.remove(os.path.join(BACKUP_DIR, old))
    return name


def list_backups():
    if not os.path.isdir(BACKUP_DIR):
        return []
    out = []
    for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if BACKUP_RE.match(f):
            st = os.stat(os.path.join(BACKUP_DIR, f))
            out.append({"name": f, "size": st.st_size, "at": iso(datetime.fromtimestamp(st.st_mtime, timezone.utc))})
    return out


def restore_backup(name):
    """Replace the live database with a backup. A safety copy of the current state is taken first."""
    src_path = os.path.join(BACKUP_DIR, name)
    if not BACKUP_RE.match(name) or not os.path.isfile(src_path):
        raise ValueError("Backup not found")
    chk = sqlite3.connect(src_path)
    try:
        ok = chk.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        tables = {r[0] for r in chk.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError:
        ok, tables = False, set()
    finally:
        chk.close()
    if not ok or not {"users", "incidents", "events", "audit"} <= tables:
        raise ValueError("This file is damaged or is not a SentinelDesk database")
    safety = make_backup("prerestore")
    src, dst = sqlite3.connect(src_path), sqlite3.connect(DB)
    try:
        with dst:
            src.backup(dst)
    finally:
        src.close()
        dst.close()
    init()                                   # upgrade older backups additively
    c = db()
    try:
        alive = {r[0] for r in c.execute("SELECT username FROM users WHERE active=1")}
    finally:
        c.close()
    for sid in [k for k, v in SESSIONS.items() if v["username"] not in alive]:
        SESSIONS.pop(sid, None)
    return safety


def system_status(c):
    now = utcnow()
    inc = c.execute("SELECT COUNT(*) n, COALESCE(SUM(status IN('New','Investigating','Contained')),0) o FROM incidents").fetchone()
    ev_files = ev_bytes = 0
    if os.path.isdir(EVIDENCE_DIR):
        for f in os.listdir(EVIDENCE_DIR):
            fp = os.path.join(EVIDENCE_DIR, f)
            if os.path.isfile(fp):
                ev_files, ev_bytes = ev_files + 1, ev_bytes + os.path.getsize(fp)
    backups = list_backups()
    age_h = round((now - when_of(backups[0]["at"])).total_seconds() / 3600, 1) if backups else None
    checks = []
    add = lambda cid, level, text: checks.append({"id": cid, "level": level, "text": text})
    weak = []
    for uname, pw in DEFAULT_PASSWORDS.items():
        r = c.execute("SELECT salt,pw_hash FROM users WHERE username=? AND active=1", (uname,)).fetchone()
        if r and hmac.compare_digest(hash_pw(pw, r["salt"]), r["pw_hash"]):
            weak.append(uname)
    add("default_passwords", "bad" if weak else "ok", ("Default password still in use for: " + ", ".join(weak)) if weak else "No default passwords are in use")
    no2fa = [r["username"] for r in c.execute("SELECT username FROM users WHERE role='admin' AND active=1 AND totp_enabled=0")]
    add("admin_2fa", "warn" if no2fa else "ok", ("Administrators without two-factor: " + ", ".join(no2fa)) if no2fa else "All administrators use two-factor")
    if not backups:
        add("backup", "warn", "No backup exists yet")
    elif age_h > 168:
        add("backup", "warn", f"The last backup is {round(age_h / 24)} days old")
    else:
        add("backup", "ok", f"Last backup {age_h} hours ago")
    if TLS_ON:
        add("tls", "ok", "HTTPS is enabled")
    elif HOST in ("127.0.0.1", "localhost", "::1"):
        add("tls", "ok", "Reachable from this computer only")
    else:
        add("tls", "warn", "Reachable over the network without HTTPS")
    cfg = notification_config()
    chan = {k: cfg[k + "_enabled"] for k in ("email", "telegram", "slack", "discord")}
    add("notifications", "ok" if any(chan.values()) else "warn", "Alert notifications are configured" if any(chan.values()) else "No notification channel is configured")
    add("webhook", "ok" if os.environ.get("SENTINEL_WEBHOOK_TOKEN") else "info", "Webhook endpoint is protected by a token" if os.environ.get("SENTINEL_WEBHOOK_TOKEN") else "Webhook endpoint is off (no SENTINEL_WEBHOOK_TOKEN)")
    chain = verify_audit(c)
    add("audit_chain", "ok" if chain["ok"] else "bad", f"Audit log chain intact ({chain['checked']} entries)" if chain["ok"] else f"Audit log was tampered with at entry #{chain['bad_id']}")
    quick = c.execute("PRAGMA quick_check").fetchone()[0]
    add("db_integrity", "ok" if quick == "ok" else "bad", "Database integrity check passed" if quick == "ok" else "Database integrity check FAILED")
    scored = [x for x in checks if x["level"] != "info"]
    live = [v for v in SESSIONS.values() if v["exp"] >= time.time()]
    tokens = [r for r in c.execute("SELECT expires_at FROM api_tokens WHERE revoked=0") if when_of(r["expires_at"]) >= now]
    return {"version": VERSION, "python": platform.python_version(), "uptime_seconds": int(time.time() - START_TIME),
            "db_bytes": os.path.getsize(DB), "evidence": {"files": ev_files, "bytes": ev_bytes},
            "counts": {"incidents": inc["n"], "open": inc["o"], "users": c.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0],
                       "assets": c.execute("SELECT COUNT(*) FROM assets").fetchone()[0], "indicators": c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]},
            "backups": {"count": len(backups), "newest": backups[0]["at"] if backups else None, "age_hours": age_h},
            "sessions": len(live), "api_tokens": len(tokens), "tls": TLS_ON, "checks": checks,
            "score": round(100 * sum(1 for x in scored if x["level"] == "ok") / len(scored)) if scored else 100}


def csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def qid(n):
    return '"' + n.replace('"', '') + '"'


def tbl_cols(c, name):
    hidden = TABLES[name].get("hidden", [])
    return [{"name": r["name"], "type": (r["type"] or "TEXT").upper(), "notnull": bool(r["notnull"]),
             "pk": bool(r["pk"]), "default": r["dflt_value"]}
            for r in c.execute(f"PRAGMA table_info({qid(name)})") if r["name"] not in hidden]


def db_choices(c):
    users = [r[0] for r in c.execute("SELECT username FROM users ORDER BY username")]
    return {"incidents.status": STATUSES, "incidents.severity": SEVERITIES,
            "incidents.category": get_lookups(c, "category", False), "incidents.source": get_lookups(c, "source", False),
            "incidents.assignee": ["Unassigned"] + users, "incidents.reporter": users,
            "users.role": list(ROLES), "lookups.kind": list(LOOKUP_KINDS), "events.kind": EVENT_KINDS,
            "events.tag": [""] + get_lookups(c, "action_type", False), "events.username": users, "incidents.tlp": TLP}


def friendly(e):
    m = str(e)
    if "NOT NULL" in m:
        return "'" + m.rsplit(".", 1)[-1] + "' is required"
    if "UNIQUE" in m:
        return "That value already exists and must be unique"
    if "FOREIGN KEY" in m:
        return "The referenced record does not exist (or other records depend on this one)"
    if "CHECK" in m:
        return "That value is not allowed for this field"
    return m


def coerce(cols, values):
    colmap = {x["name"]: x for x in cols}
    out = {}
    for k, v in values.items():
        if k not in colmap:
            continue
        if v is None or (isinstance(v, str) and v.strip() == ""):
            out[k] = None
            continue
        if colmap[k]["type"].startswith("INT"):
            try:
                out[k] = int(v)
            except (TypeError, ValueError):
                raise ValueError(f"'{k}' must be a whole number")
        elif k in DATE_COLS:
            try:
                dt = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(f"'{k}' must be a valid date and time")
            out[k] = iso(dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc))
        else:
            out[k] = str(v).strip()
    return out


def admin_guard(c, me, row, new_role=None, new_active=None, deleting=False):
    """Never allow removing the last active administrator, or locking yourself out."""
    if row["role"] != "admin" or not row["active"]:
        return
    losing = deleting or (new_role is not None and new_role != "admin") or (new_active is not None and not new_active)
    if not losing:
        return
    if row["username"] == me:
        raise ValueError("You cannot remove your own administrator access")
    if not c.execute("SELECT 1 FROM users WHERE role='admin' AND active=1 AND id!=?", (row["id"],)).fetchone():
        raise ValueError("At least one active administrator is required")


def lookup_usage(c, row):
    _, tbl, col = LOOKUP_KINDS[row["kind"]]
    return c.execute(f"SELECT COUNT(*) FROM {tbl} WHERE {col}=?", (row["name"],)).fetchone()[0]


def db_insert(c, me, table, values):
    cfg = TABLES[table]
    if cfg.get("readonly") or cfg.get("no_insert"):
        raise ValueError("Rows cannot be added to this table")
    v = coerce(tbl_cols(c, table), values)
    now = iso(utcnow())
    if table == "incidents":
        for k in ("title", "description", "asset"):
            if not v.get(k):
                raise ValueError(f"'{k}' is required")
        v["id"] = v.get("id") or next_id(c)
        v["created_at"] = v.get("created_at") or now
        v["updated_at"] = v.get("updated_at") or v["created_at"]
        v["status"] = v.get("status") or "New"
        v["assignee"] = v.get("assignee") or "Unassigned"
        v["reporter"] = v.get("reporter") or me
        v["source"] = v.get("source") or "Other"
        if v.get("severity") not in SEVERITIES or v["status"] not in STATUSES:
            raise ValueError("Choose a valid severity and status")
        if v.get("tlp") and v["tlp"] not in TLP:
            raise ValueError("Invalid TLP marking")
        if not v.get("category"):
            raise ValueError("'category' is required")
        v["due_at"] = v.get("due_at") or iso(parse(v["created_at"]) + timedelta(hours=get_sla(c)[v["severity"]]))
    elif table == "events":
        v["at"] = v.get("at") or now
        v["username"] = v.get("username") or me
        v["tag"] = v.get("tag") or ""
        if v.get("kind") not in EVENT_KINDS or not v.get("text") or not v.get("incident_id"):
            raise ValueError("Incident, kind and text are required")
    elif table == "users":
        pw = str(values.get("password", ""))
        if not strong_password(pw):
            raise ValueError("Password needs 8+ characters with letters and numbers")
        v["username"] = re.sub(r"[^a-z0-9._-]", "", (v.get("username") or "").lower())
        if len(v["username"]) < 3 or not v.get("full_name") or v.get("role") not in ROLES:
            raise ValueError("Username (3+ characters), full name and role are required")
        v["salt"] = secrets.token_hex(16)
        v["pw_hash"] = hash_pw(pw, v["salt"])
        v["active"] = 1 if v.get("active") is None else v["active"]
        v["created_at"] = now
        v["email"] = v.get("email") or ""
    elif table == "lookups":
        v["name"] = (v.get("name") or "")[:60]
        if v.get("kind") not in LOOKUP_KINDS or not v["name"]:
            raise ValueError("Kind and name are required")
        v["sort"] = (c.execute("SELECT COALESCE(MAX(sort),0)+1 FROM lookups WHERE kind=?", (v["kind"],)).fetchone()[0])
    v = {k: x for k, x in v.items() if x is not None}
    try:
        cur = c.execute(f"INSERT INTO {qid(table)}({','.join(qid(k) for k in v)}) VALUES({','.join('?' * len(v))})", list(v.values()))
    except sqlite3.IntegrityError as e:
        raise ValueError(friendly(e))
    key = v.get(cfg["pk"], cur.lastrowid)
    if table == "incidents":
        apply_playbook(c, key, v["category"])
    audit(c, me, "db.insert", f"{table} #{key}")
    return key


def pk_value(c, table, pk):
    col = next(x for x in tbl_cols(c, table) if x["pk"])
    return int(pk) if col["type"].startswith("INT") else str(pk)


def db_update(c, me, table, pk, values):
    cfg = TABLES[table]
    if cfg.get("readonly"):
        raise ValueError("This table is read-only to protect the audit trail")
    pk = pk_value(c, table, pk)
    row = c.execute(f"SELECT * FROM {qid(table)} WHERE {qid(cfg['pk'])}=?", (pk,)).fetchone()
    if not row:
        raise ValueError("Row not found")
    v = coerce(tbl_cols(c, table), values)
    v.pop(cfg["pk"], None)
    now = iso(utcnow())
    if table == "incidents":
        if "severity" in v and v["severity"] not in SEVERITIES or "status" in v and v["status"] not in STATUSES:
            raise ValueError("Choose a valid severity and status")
        v["updated_at"] = now
    elif table == "events":
        if "kind" in v and v["kind"] not in EVENT_KINDS:
            raise ValueError("Invalid event kind")
        if "tag" in v and v["tag"] is None:
            v["tag"] = ""
    elif table == "users":
        admin_guard(c, me, row, v.get("role") or row["role"], row["active"] if v.get("active") is None else v["active"])
        if "username" in v:
            raise ValueError("Usernames cannot be changed")
        if v.get("role", row["role"]) not in ROLES:
            raise ValueError("Invalid role")
        pw = str(values.get("password", "") or "")
        if pw:
            if not strong_password(pw):
                raise ValueError("Password needs 8+ characters with letters and numbers")
            v["salt"] = secrets.token_hex(16)
            v["pw_hash"] = hash_pw(pw, v["salt"])
    elif table == "lookups":
        v.pop("kind", None)
        if "name" in v:
            v["name"] = (v["name"] or "")[:60]
            if not v["name"]:
                raise ValueError("Name is required")
    elif table == "settings":
        if not row["key"].startswith("sla_"):
            raise ValueError("Unknown setting")
        try:
            hrs = int(v.get("value"))
        except (TypeError, ValueError):
            raise ValueError("Hours must be a whole number")
        if not 1 <= hrs <= 720:
            raise ValueError("Hours must be between 1 and 720")
        v = {"value": str(hrs)}
    notnull = {x["name"] for x in tbl_cols(c, table) if x["notnull"]}
    v = {k: x for k, x in v.items() if not (x is None and k in notnull)}
    if not v:
        return pk
    try:
        if table == "lookups" and "name" in v and v["name"] != row["name"]:  # rename everywhere it is used
            _, tbl, col = LOOKUP_KINDS[row["kind"]]
            c.execute(f"UPDATE {tbl} SET {col}=? WHERE {col}=?", (v["name"], row["name"]))
        c.execute(f"UPDATE {qid(table)} SET {','.join(qid(k) + '=?' for k in v)} WHERE {qid(cfg['pk'])}=?", list(v.values()) + [pk])
    except sqlite3.IntegrityError as e:
        raise ValueError(friendly(e))
    audit(c, me, "db.update", f"{table} #{pk}: {', '.join(k for k in v if k not in ('pw_hash', 'salt'))}")
    return pk


def db_delete(c, me, table, pk):
    cfg = TABLES[table]
    if cfg.get("readonly") or cfg.get("no_delete"):
        raise ValueError("Rows cannot be deleted from this table")
    pk = pk_value(c, table, pk)
    row = c.execute(f"SELECT * FROM {qid(table)} WHERE {qid(cfg['pk'])}=?", (pk,)).fetchone()
    if not row:
        raise ValueError("Row not found")
    if table == "users":
        admin_guard(c, me, row, deleting=True)
        if row["username"] == me:
            raise ValueError("You cannot delete your own account")
    if table == "lookups":
        n = lookup_usage(c, row)
        if n:
            raise ValueError(f"'{row['name']}' is used by {n} record(s). Disable it instead of deleting it.")
    if table == "incidents":
        purge_evidence_files(c, row["id"])
    c.execute(f"DELETE FROM {qid(table)} WHERE {qid(cfg['pk'])}=?", (pk,))
    audit(c, me, "db.delete", f"{table} #{pk}")


def run_query(sql):
    """Read-only SQL console: one SELECT statement, no writes, password hashes unreadable."""
    sql = sql.strip().rstrip(";").strip()
    if not sql or ";" in sql:
        raise ValueError("Enter a single SELECT statement")
    if sql.split(None, 1)[0].lower() not in ("select", "with", "explain"):
        raise ValueError("Only SELECT queries are allowed in the console")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")

    def auth(action, a1, a2, dbname, src):
        if action in (21, 31, 33):  # SELECT, FUNCTION, RECURSIVE
            return sqlite3.SQLITE_OK
        if action == 20:  # READ column
            return sqlite3.SQLITE_DENY if (a1 == "users" and a2 in ("pw_hash", "salt", "totp_secret")) else sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    conn.set_authorizer(auth)
    t0 = time.time()
    try:
        cur = conn.execute(sql)
        rows = cur.fetchmany(501)
        cols = [x[0] for x in cur.description or []]
    except sqlite3.Error as e:
        raise ValueError("SQL error: " + str(e))
    finally:
        conn.close()
    return {"columns": cols, "rows": [list(r) for r in rows[:500]], "truncated": len(rows) > 500,
            "ms": round((time.time() - t0) * 1000, 1)}


def next_id(c):
    y = utcnow().year
    n = c.execute("SELECT MAX(CAST(SUBSTR(id,10) AS INTEGER)) FROM incidents WHERE id LIKE ?",
                  (f"INC-{y}-%",)).fetchone()[0] or 0
    return f"INC-{y}-{n + 1:04d}"


def sla_state(r):
    due = parse(r["due_at"])
    created = parse(r["created_at"])
    if r["resolved_at"]:
        return "met" if parse(r["resolved_at"]) <= due else "breached"
    left = (due - utcnow()).total_seconds()
    if left < 0:
        return "breached"
    return "at_risk" if left < 0.25 * (due - created).total_seconds() else "ok"


def inc_summary(r):
    ks = r.keys()
    extra = {k: r[k] for k in ("n_ioc", "n_ev", "n_chk", "n_chk_done") if k in ks}
    risk, band, crit = risk_of(r["severity"], r["asset"])
    return {**extra, "risk": risk, "risk_band": band, "asset_crit": crit, "asset_registered": (r["asset"] or "").strip().lower() in ASSET_CRIT,
            "tlp": r["tlp"] if "tlp" in ks else "AMBER", "mitre": mitre_list(r["mitre"]) if "mitre" in ks else [],
            "id": r["id"], "title": r["title"], "category": r["category"], "severity": r["severity"],
            "status": r["status"], "asset": r["asset"], "assignee": r["assignee"], "reporter": r["reporter"],
            "source": r["source"], "created_at": r["created_at"], "updated_at": r["updated_at"],
            "due_at": r["due_at"], "resolved_at": r["resolved_at"], "closed_at": r["closed_at"],
            "sla": sla_state(r)}


def inc_detail(c, r):
    d = inc_summary(r)
    d["description"] = r["description"]
    d["resolution"] = r["resolution"]
    d["root_cause"], d["lessons"] = r["root_cause"], r["lessons"]
    d["events"] = [dict(e) for e in c.execute(
        "SELECT kind,tag,text,username,at FROM events WHERE incident_id=? ORDER BY id", (r["id"],))]
    d["iocs"] = []
    for e in c.execute("SELECT id,type,value,note,added_by,added_at FROM iocs WHERE incident_id=? ORDER BY id", (r["id"],)).fetchall():
        x = dict(e)
        x["seen"] = [o[0] for o in c.execute("SELECT DISTINCT incident_id FROM iocs WHERE type=? AND value=? AND incident_id!=?", (x["type"], x["value"], r["id"]))]
        d["iocs"].append(x)
    d["evidence"] = [dict(e) for e in c.execute(
        "SELECT id,filename,size,sha256,note,uploaded_by,uploaded_at FROM evidence WHERE incident_id=? ORDER BY id", (r["id"],))]
    d["checklist"] = [dict(e) for e in c.execute(
        "SELECT id,text,text_ar,done,done_by,done_at FROM checklist WHERE incident_id=? ORDER BY sort,id", (r["id"],))]
    d["related"] = related_incidents(c, r)
    d["framework"] = framework_of(r["category"])
    return d


LIST_SQL = """SELECT i.*, (SELECT COUNT(*) FROM iocs WHERE incident_id=i.id) AS n_ioc,
              (SELECT COUNT(*) FROM evidence WHERE incident_id=i.id) AS n_ev,
              (SELECT COUNT(*) FROM checklist WHERE incident_id=i.id) AS n_chk,
              (SELECT COUNT(*) FROM checklist WHERE incident_id=i.id AND done=1) AS n_chk_done
              FROM incidents i ORDER BY created_at DESC"""


def create_incident(c, user, v, when=None):
    iid = next_id(c)
    t = when or utcnow()
    due = t + timedelta(hours=get_sla(c)[v["severity"]])
    c.execute("""INSERT INTO incidents(id,title,description,category,severity,status,asset,source,assignee,reporter,
                 created_at,updated_at,due_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (iid, v["title"], v["description"], v["category"], v["severity"], "New", v["asset"], v["source"],
               v["assignee"], user, iso(t), iso(t), iso(due)))
    event(c, iid, "created", "Incident reported.", user, iso(t))
    apply_playbook(c, iid, v["category"])
    audit(c, user, "incident.create", iid)
    return iid



# ---------------------------------------------------------------- two-factor authentication (RFC 6238 TOTP)
def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7fffffff) % 1000000:06d}"


def totp_verify(secret, code, username=None, now=None):
    """Accept the current, previous or next 30 s code; a code can be used only once per user."""
    code = re.sub(r"\s", "", str(code or ""))
    if not secret or not re.fullmatch(r"\d{6}", code):
        return False
    step = int((now if now is not None else time.time()) // 30)
    for off in (0, -1, 1):
        if hmac.compare_digest(totp_at(secret, step + off), code):
            if username:
                if LAST_TOTP.get(username, -1) >= step + off:
                    return False  # replay of an already-used code
                LAST_TOTP[username] = step + off
            return True
    return False


# ---------------------------------------------------------------- indicators of compromise
def refang(v):
    v = v.strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    return re.sub(r"^hxxp", "http", v, flags=re.I)


def detect_ioc_type(v):
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", v):
        return "hash"
    if re.match(r"^[a-z][a-z0-9+.-]*://\S+$", v, re.I):
        return "url"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", v):
        return "email"
    if re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z]{2,}", v):
        return "domain"
    return "other"


def clean_ioc(raw_type, raw_value):
    v = refang(str(raw_value or ""))[:500]
    if not v or re.search(r"[\x00-\x1f]", v):
        raise ValueError("Enter an indicator value")
    t = str(raw_type or "").lower()
    if t not in IOC_TYPES:
        t = detect_ioc_type(v)
    if t in ("ip", "domain", "hash", "email"):
        v = v.lower()
    return t, v


# ---------------------------------------------------------------- evidence (stored on disk, integrity-hashed)
def safe_filename(name):
    name = os.path.basename(str(name or "").replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f\"<>|:*?]", "_", name).strip(" .")[:150]
    return name or "file"


def save_evidence(c, iid, user, filename, raw, note=""):
    if not raw:
        raise ValueError("The file is empty")
    if len(raw) > EVIDENCE_MAX:
        raise ValueError(f"File is larger than {EVIDENCE_MAX // 1048576} MB")
    sha = hashlib.sha256(raw).hexdigest()
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    stored = secrets.token_hex(16) + ".bin"          # the user-supplied name never touches the filesystem
    with open(os.path.join(EVIDENCE_DIR, stored), "xb") as f:
        f.write(raw)
    name = safe_filename(filename)
    cur = c.execute("INSERT INTO evidence(incident_id,filename,size,sha256,stored_name,note,uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?,?)",
                    (iid, name, len(raw), sha, stored, str(note or "")[:300], user, iso(utcnow())))
    event(c, iid, "evidence", f"Evidence added: {name} ({len(raw)} bytes, SHA-256 {sha[:16]}…)", user)
    audit(c, user, "evidence.upload", f"{iid}: {name} sha256={sha}")
    return cur.lastrowid, sha


def purge_evidence_files(c, iid):
    for r in c.execute("SELECT stored_name FROM evidence WHERE incident_id=?", (iid,)).fetchall():
        try:
            os.remove(os.path.join(EVIDENCE_DIR, os.path.basename(r["stored_name"])))
        except OSError:
            pass


# ---------------------------------------------------------------- playbooks / checklist
def apply_playbook(c, iid, category, only_if_empty=True):
    if only_if_empty and c.execute("SELECT 1 FROM checklist WHERE incident_id=?", (iid,)).fetchone():
        return 0
    steps = PLAYBOOKS.get(category, PLAYBOOK_DEFAULT)
    for i, (en, ar) in enumerate(steps):
        c.execute("INSERT INTO checklist(incident_id,text,text_ar,sort) VALUES(?,?,?,?)", (iid, en, ar, i))
    return len(steps)


# ---------------------------------------------------------------- shared incident operations (single + bulk)
def do_status(c, r, st, un):
    ra = (r["resolved_at"] or iso(utcnow())) if st == "Resolved" else None
    c.execute("UPDATE incidents SET status=?, resolved_at=? WHERE id=?", (st, ra, r["id"]))
    event(c, r["id"], "status", f"Status changed to {st}.", un)
    audit(c, un, "incident.status", f"{r['id']} -> {st}")


def do_assign(c, r, a, un):
    c.execute("UPDATE incidents SET assignee=? WHERE id=?", (a, r["id"]))
    event(c, r["id"], "assign", f"Assigned to {dn(c, a)}." if a != "Unassigned" else "Assignment removed.", un)
    audit(c, un, "incident.assign", f"{r['id']} -> {a}")


def do_severity(c, r, sv, un):
    due = parse(r["created_at"]) + timedelta(hours=get_sla(c)[sv])
    c.execute("UPDATE incidents SET severity=?, due_at=? WHERE id=?", (sv, iso(due), r["id"]))
    event(c, r["id"], "severity", f"Severity changed from {r['severity']} to {sv}.", un)
    audit(c, un, "incident.severity", f"{r['id']} -> {sv}")


def valid_assignee(c, a):
    return a == "Unassigned" or bool(c.execute("SELECT 1 FROM users WHERE username=? AND active=1 AND role!='viewer'", (a,)).fetchone())


def mitre_list(raw):
    return [x for x in str(raw or "").split(",") if x in MITRE]


# ---------------------------------------------------------------- related incidents, search, alerts, reports
def related_incidents(c, r):
    out = {}
    q = """SELECT DISTINCT i.*, a.value AS v FROM iocs a JOIN iocs b ON a.type=b.type AND a.value=b.value AND b.incident_id!=a.incident_id
           JOIN incidents i ON i.id=b.incident_id WHERE a.incident_id=?"""
    for x in c.execute(q, (r["id"],)):
        out.setdefault(x["id"], {"row": x, "reasons": []})["reasons"].append({"kind": "ioc", "value": x["v"]})
    for x in c.execute("SELECT * FROM incidents WHERE asset=? AND id!=?", (r["asset"], r["id"])):
        out.setdefault(x["id"], {"row": x, "reasons": []})["reasons"].append({"kind": "asset", "value": x["asset"]})
    res = [{"id": v["row"]["id"], "title": v["row"]["title"], "severity": v["row"]["severity"], "status": v["row"]["status"],
            "created_at": v["row"]["created_at"], "reasons": v["reasons"]} for v in out.values()]
    res.sort(key=lambda x: (-len(x["reasons"]), x["created_at"]), reverse=False)
    return res[:10]


def like_pat(q):
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search_all(c, q):
    q = q.strip()[:80]
    if len(q) < 2:
        return {"incidents": [], "iocs": [], "assets": []}
    pat = like_pat(q)
    inc = [{"id": r["id"], "title": r["title"], "severity": r["severity"], "status": r["status"], "asset": r["asset"]} for r in c.execute(
        """SELECT id,title,severity,status,asset FROM incidents WHERE id LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR asset LIKE ? ESCAPE '\\'
           OR description LIKE ? ESCAPE '\\' ORDER BY created_at DESC LIMIT 8""", (pat, pat, pat, pat))]
    iocs = [dict(r) for r in c.execute(
        "SELECT type,value,incident_id FROM iocs WHERE value LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 6", (pat,))]
    assets = [{"name": r[0], "count": r[1]} for r in c.execute(
        "SELECT asset,COUNT(*) FROM incidents WHERE asset LIKE ? ESCAPE '\\' GROUP BY asset ORDER BY COUNT(*) DESC LIMIT 5", (pat,))]
    return {"incidents": inc, "iocs": iocs, "assets": assets}


def alerts(c):
    rows = [r for r in c.execute("SELECT * FROM incidents WHERE status IN('New','Investigating','Contained')")]
    br, ar, un = [], [], []
    for r in rows:
        s = sla_state(r)
        if s == "breached":
            br.append(r)
        elif s == "at_risk":
            ar.append(r)
        if r["assignee"] == "Unassigned" and r["severity"] in ("Critical", "High"):
            un.append(r)
    f = lambda L: [inc_summary(r) for r in sorted(L, key=lambda r: r["due_at"])[:8]]
    return {"breached": f(br), "at_risk": f(ar), "unassigned": f(un),
            "count": len(br) + len(ar) + len(un), "counts": {"breached": len(br), "at_risk": len(ar), "unassigned": len(un)}}


def mtta_hours(c, since=None):
    """Mean time to acknowledge: report time -> first move to Investigating."""
    q = """SELECT i.created_at, MIN(e.at) AS ack FROM incidents i JOIN events e ON e.incident_id=i.id
           WHERE e.kind='status' AND e.text LIKE 'Status changed to Investigating%'"""
    params = []
    if since:
        q += " AND i.created_at>=?"
        params.append(iso(since))
    q += " GROUP BY i.id"
    vals = [(parse(r["ack"]) - parse(r["created_at"])).total_seconds() for r in c.execute(q, params)]
    vals = [v for v in vals if v >= 0]
    return round(sum(vals) / len(vals) / 3600, 2) if vals else None


def period_report(c, days):
    now = utcnow()
    since = now - timedelta(days=days)
    rows = c.execute("SELECT * FROM incidents").fetchall()
    created = [r for r in rows if parse(r["created_at"]) >= since]
    resolved = [r for r in rows if r["resolved_at"] and parse(r["resolved_at"]) >= since]
    closed = [r for r in rows if r["closed_at"] and parse(r["closed_at"]) >= since]
    open_now = [r for r in rows if r["status"] in OPEN_STATUSES]
    mttr = (sum((parse(r["resolved_at"]) - parse(r["created_at"])).total_seconds() for r in resolved) / len(resolved) / 3600) if resolved else None
    met = sum(1 for r in resolved if sla_state(r) == "met")

    def tally(key, rs, split=False):
        out = {}
        for r in rs:
            for k in (mitre_list(r[key]) if split else [r[key]]):
                out[k] = out.get(k, 0) + 1
        return [{"name": k, "value": v} for k, v in sorted(out.items(), key=lambda x: -x[1])]
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    notable = sorted([r for r in created if r["severity"] in ("Critical", "High")], key=lambda r: (-sev_rank[r["severity"]], r["created_at"]))[:12]
    return {"days": days, "since": iso(since), "until": iso(now),
            "totals": {"reported": len(created), "resolved": len(resolved), "closed": len(closed), "open_now": len(open_now),
                       "breached_now": sum(1 for r in open_now if sla_state(r) == "breached"),
                       "mttr_hours": mttr, "mtta_hours": mtta_hours(c, since), "sla_met_pct": round(100 * met / len(resolved)) if resolved else None},
            "by_severity": [{"name": s, "value": sum(1 for r in created if r["severity"] == s)} for s in SEVERITIES[::-1]],
            "by_category": tally("category", created), "by_source": tally("source", created), "by_mitre": tally("mitre", created, True),
            "top_assets": tally("asset", created)[:6], "notable": [inc_summary(r) for r in notable],
            "risk": period_risk(created), "framework": period_framework(created), **team_performance(rows, resolved, since)}


ISO_CTRL = {"A.5.14": "Information transfer", "A.5.15": "Access control", "A.5.24": "Information security incident management planning and preparation",
            "A.5.25": "Assessment and decision on information security events", "A.5.26": "Response to information security incidents",
            "A.5.27": "Learning from information security incidents", "A.5.28": "Collection of evidence", "A.5.34": "Privacy and protection of PII",
            "A.5.36": "Compliance with policies, rules and standards for information security", "A.6.3": "Information security awareness, education and training",
            "A.6.4": "Disciplinary process", "A.8.5": "Secure authentication", "A.8.6": "Capacity management", "A.8.7": "Protection against malware",
            "A.8.8": "Management of technical vulnerabilities", "A.8.12": "Data leakage prevention", "A.8.13": "Information backup", "A.8.15": "Logging", "A.8.16": "Monitoring activities",
            "A.8.20": "Networks security"}
NIST_CSF = {"DE.AE": "Adverse Event Analysis", "DE.CM": "Continuous Monitoring", "RS.MA": "Incident Management", "RS.AN": "Incident Analysis",
            "RS.CO": "Incident Response Reporting and Communication", "RS.MI": "Incident Mitigation", "RC.RP": "Incident Recovery Plan Execution",
            "PR.AA": "Identity Management, Authentication, and Access Control", "PR.AT": "Awareness and Training", "PR.DS": "Data Security",
            "PR.IR": "Technology Infrastructure Resilience", "PR.PS": "Platform Security", "ID.RA": "Risk Assessment", "GV.PO": "Policy"}
FRAMEWORK_BASE = (["A.5.24", "A.5.25", "A.5.26", "A.5.27", "A.5.28"], ["DE.AE", "RS.MA", "RS.AN", "RS.MI", "RC.RP"])
FRAMEWORK = {"Malware": (["A.8.7", "A.8.16"], ["DE.CM"]), "Phishing": (["A.6.3", "A.8.7"], ["PR.AT", "RS.CO"]),
             "Unauthorized Access": (["A.5.15", "A.8.5"], ["PR.AA"]), "DDoS": (["A.8.6", "A.8.20"], ["PR.IR"]),
             "Vulnerability Exploit": (["A.8.8"], ["ID.RA", "PR.PS"]), "Insider Threat": (["A.6.4", "A.8.12", "A.8.15"], ["DE.CM", "PR.AA"]),
             "Data Leak": (["A.5.34", "A.8.12"], ["PR.DS"]), "Policy Violation": (["A.5.36", "A.6.4"], ["GV.PO"]), "Ransomware": (["A.8.7", "A.8.13"], ["DE.CM", "PR.DS"])}


def framework_of(category):
    """Indicative mapping of an incident category to ISO/IEC 27001:2022 Annex A controls and NIST CSF 2.0 categories."""
    iso_ids, nist_ids = FRAMEWORK.get(category, ([], []))
    return {"iso": [{"id": i, "name": ISO_CTRL[i]} for i in FRAMEWORK_BASE[0] + iso_ids],
            "nist": [{"id": i, "name": NIST_CSF[i]} for i in FRAMEWORK_BASE[1] + nist_ids], "specific": bool(iso_ids)}


def period_framework(created):
    out = {}
    for r in created:
        out[r["category"]] = out.get(r["category"], 0) + 1
    return [dict(category=k, count=v, **framework_of(k)) for k, v in sorted(out.items(), key=lambda kv: (-kv[1], kv[0]))]


def team_performance(rows, resolved, since):
    rid = {r["id"] for r in resolved}
    by_sev = []
    for sv in reversed(SEVERITIES):
        rs = [r for r in resolved if r["severity"] == sv]
        secs = [(parse(r["resolved_at"]) - parse(r["created_at"])).total_seconds() for r in rs if r["resolved_at"]]
        by_sev.append({"name": sv, "resolved": len(rs), "mttr_hours": round(sum(secs) / len(secs) / 3600, 1) if secs else None,
                       "sla_met_pct": round(100 * sum(1 for r in rs if sla_state(r) == "met") / len(rs)) if rs else None})
    team = {}
    for r in rows:
        a = r["assignee"]
        if a == "Unassigned":
            continue
        t = team.setdefault(a, {"name": a, "assigned": 0, "open": 0, "resolved": 0, "_secs": 0, "_n": 0, "_met": 0})
        t["assigned"] += parse(r["created_at"]) >= since
        t["open"] += r["status"] in OPEN_STATUSES
        if r["id"] in rid:
            t["resolved"] += 1
            t["_met"] += sla_state(r) == "met"
            if r["resolved_at"]:
                t["_secs"], t["_n"] = t["_secs"] + (parse(r["resolved_at"]) - parse(r["created_at"])).total_seconds(), t["_n"] + 1
    out = []
    for t in team.values():
        out.append({"name": t["name"], "assigned": t["assigned"], "open": t["open"], "resolved": t["resolved"],
                    "mttr_hours": round(t["_secs"] / t["_n"] / 3600, 1) if t["_n"] else None,
                    "sla_met_pct": round(100 * t["_met"] / t["resolved"]) if t["resolved"] else None})
    return {"sla_by_severity": by_sev, "team": sorted([x for x in out if x["assigned"] or x["resolved"] or x["open"]], key=lambda x: (-x["resolved"], -x["open"], x["name"]))}


def period_risk(created):
    per, bands = {}, {b: 0 for b in BANDS}
    for r in created:
        sc, band, crit = risk_of(r["severity"], r["asset"])
        bands[band] += 1
        a = per.setdefault(r["asset"], {"name": r["asset"], "crit": crit, "count": 0, "value": 0})
        a["count"] += 1
        a["value"] += sc
    scores = [risk_of(r["severity"], r["asset"])[0] for r in created]
    return {"avg": round(sum(scores) / len(scores)) if scores else None,
            "bands": [{"name": b, "value": bands[b]} for b in BANDS],
            "top_assets": sorted(per.values(), key=lambda x: (-x["value"], x["name"]))[:6],
            "repeat_assets": sorted([{"name": a["name"], "value": a["count"], "crit": a["crit"]} for a in per.values() if a["count"] >= 2],
                                    key=lambda x: (-x["value"], x["name"]))[:6]}


# ---------------------------------------------------------------- dashboard
def dashboard(c, days=14):
    days = days if days in (7, 14, 30, 90) else 14
    now = utcnow()
    rows = c.execute("SELECT * FROM incidents").fetchall()
    open_rows = [r for r in rows if r["status"] in OPEN_STATUSES]
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    breached = [r for r in open_rows if sla_state(r) == "breached"]
    since30 = now - timedelta(days=30)
    res = [r for r in rows if r["resolved_at"] and parse(r["resolved_at"]) >= since30]
    mttr = (sum((parse(r["resolved_at"]) - parse(r["created_at"])).total_seconds() for r in res) / len(res) / 3600) if res else None
    met = sum(1 for r in res if sla_state(r) == "met")
    day_list = [(now - timedelta(days=i)).date() for i in range(days - 1, -1, -1)]
    created = {d: 0 for d in day_list}
    resolved = {d: 0 for d in day_list}
    hours = [0] * 24
    for r in rows:
        t = parse(r["created_at"])
        hours[t.hour] += 1
        d = t.date()
        if d in created:
            created[d] += 1
        if r["resolved_at"]:
            d = parse(r["resolved_at"]).date()
            if d in resolved:
                resolved[d] += 1

    def count(key, rs):
        out = {}
        for r in rs:
            out[r[key]] = out.get(r[key], 0) + 1
        return out

    cats = sorted(count("category", rows).items(), key=lambda x: -x[1])
    assets = sorted(count("asset", rows).items(), key=lambda x: -x[1])[:5]
    mitre = {}
    for r in rows:
        for m in mitre_list(r["mitre"]):
            mitre[m] = mitre.get(m, 0) + 1
    work = {}
    for r in open_rows:
        w = work.setdefault(r["assignee"], {"name": r["assignee"], "open": 0, "critical": 0, "breached": 0})
        w["open"] += 1
        w["critical"] += r["severity"] in ("Critical", "High")
        w["breached"] += sla_state(r) == "breached"
    attention = sorted(open_rows, key=lambda r: (sla_state(r) != "breached", -risk_of(r["severity"], r["asset"])[0], -sev_rank[r["severity"]], r["due_at"]))[:6]
    recent = c.execute("""SELECT e.incident_id, e.kind, e.text, e.username, e.at, i.title FROM events e
                          JOIN incidents i ON i.id=e.incident_id ORDER BY e.id DESC LIMIT 10""").fetchall()
    n = lambda sev: sum(1 for r in open_rows if r["severity"] == sev)
    unassigned_hot = sum(1 for r in open_rows if r["assignee"] == "Unassigned" and r["severity"] in ("Critical", "High"))
    score = min(100, 10 * n("Critical") + 4 * n("High") + 2 * n("Medium") + n("Low") + 3 * min(len(breached), 8) + 3 * unassigned_hot)
    level = "low" if score < 15 else "guarded" if score < 40 else "elevated" if score < 70 else "severe"
    chk = c.execute("SELECT COUNT(*), COALESCE(SUM(done),0) FROM checklist WHERE incident_id IN (SELECT id FROM incidents WHERE status IN('New','Investigating','Contained'))").fetchone()
    return {
        "days": days,
        "kpis": {"total": len(rows), "open": len(open_rows),
                 "critical_open": n("Critical"), "breached": len(breached),
                 "unassigned": sum(1 for r in open_rows if r["assignee"] == "Unassigned"),
                 "resolved_30d": len(res), "mttr_hours": mttr, "mtta_hours": mtta_hours(c, since30),
                 "sla_met_pct": round(100 * met / len(res)) if res else None,
                 "iocs": c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
                 "evidence": c.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
                 "playbook_pct": round(100 * chk[1] / chk[0]) if chk[0] else None},
        "posture": {"score": score, "level": level},
        "open_by_severity": [{"name": s, "value": n(s)} for s in SEVERITIES[::-1]],
        "by_severity": [{"name": s, "value": sum(1 for r in rows if r["severity"] == s)} for s in SEVERITIES[::-1]],
        "by_status": [{"name": s, "value": sum(1 for r in rows if r["status"] == s)} for s in STATUSES],
        "by_category": [{"name": k, "value": v} for k, v in cats],
        "by_mitre": [{"name": k, "value": mitre[k]} for k in MITRE if k in mitre],
        "top_assets": [{"name": k, "value": v} for k, v in assets],
        "workload": sorted(work.values(), key=lambda w: (-w["open"], w["name"])),
        "by_hour_utc": hours,
        "trend": [{"date": d.isoformat(), "created": created[d], "resolved": resolved[d]} for d in day_list],
        "attention": [inc_summary(r) for r in attention],
        "risk": risk_overview(open_rows),
        "recent": [dict(r) for r in recent],
    }


# ---------------------------------------------------------------- demo data
DEMO = [
    # title, description, category, severity, asset, source, age_hours, final_status, assignee, resolve_hours
    ("Ransomware activity on HR workstation", "EDR flagged mass file encryption and a ransom note on HR-WS-07. Host isolated from the network.", "Malware", "Critical", "HR-WS-07", "EDR alert", 650, "Closed", "analyst", 3),
    ("Credential phishing wave targeting Finance", "Fake bank-portal emails requested credentials. 14 recipients, 2 users clicked the link.", "Phishing", "High", "Mail gateway", "Email gateway", 600, "Closed", "sara", 6),
    ("Brute-force attempts on VPN gateway", "Over 3,000 failed logins from rotating IPs within 40 minutes.", "Unauthorized Access", "Medium", "VPN-GW-01", "Firewall / IDS", 540, "Closed", "analyst", 20),
    ("Public web server hit by HTTP flood", "Traffic spike of 40x baseline caused slow responses on the student portal.", "DDoS", "High", "Portal web server", "SIEM alert", 480, "Closed", "sara", 11),
    ("Unpatched Apache Struts instance exploited", "Scanner found a webshell on a legacy reporting server after CVE exploitation.", "Vulnerability Exploit", "Critical", "REPORT-LEG-02", "Threat intel", 420, "Closed", "admin", 9),
    ("USB storage used to copy research data", "DLP alert: 2.3 GB of project files copied to a personal USB drive after hours.", "Insider Threat", "High", "LAB-PC-14", "SIEM alert", 360, "Closed", "analyst", 7),
    ("Customer list found in public paste site", "Threat-intel feed matched 1,200 customer emails on a public paste.", "Data Leak", "High", "CRM database", "Threat intel", 310, "Resolved", "sara", 8),
    ("Admin account used from unusual country", "Impossible-travel alert for a domain admin sign-in from a new region.", "Unauthorized Access", "High", "Active Directory", "SIEM alert", 260, "Closed", "admin", 5),
    ("Malicious macro document opened", "Excel attachment spawned PowerShell and contacted a known C2 domain.", "Malware", "Medium", "ACC-WS-03", "EDR alert", 220, "Closed", "analyst", 18),
    ("Shadow IT cloud storage in use", "Proxy logs show staff syncing internal documents to an unapproved cloud drive.", "Policy Violation", "Low", "Proxy", "Audit / review", 200, "Closed", "sara", 40),
    ("CEO impersonation email (BEC)", "Spoofed executive email asked finance to change a supplier bank account.", "Phishing", "High", "Mail gateway", "User report", 150, "Resolved", "analyst", 5),
    ("Outdated TLS on payment page", "External scan found TLS 1.0 enabled on the payment microsite.", "Vulnerability Exploit", "Medium", "Payments site", "Audit / review", 120, "Contained", "sara", None),
    ("Port scan from internal host", "Internal workstation scanned 10.0.4.0/24 across 1,000+ ports.", "Insider Threat", "Medium", "ENG-PC-22", "Firewall / IDS", 96, "Investigating", "analyst", None),
    ("Database backup exposed on file share", "Unencrypted SQL backup readable by Everyone on a departmental share.", "Data Leak", "High", "FILESRV-02", "Audit / review", 80, "Investigating", "admin", None),
    ("Suspicious PowerShell on domain controller", "Encoded PowerShell command executed by a service account on DC-01.", "Malware", "Critical", "DC-01", "EDR alert", 30, "Investigating", "analyst", None),
    ("DNS tunnelling pattern detected", "High-entropy TXT queries to a newly registered domain from the guest Wi-Fi VLAN.", "Unauthorized Access", "Medium", "Guest Wi-Fi", "SIEM alert", 52, "New", "Unassigned", None),
    ("Lost laptop with unencrypted disk", "Employee reported a stolen laptop; disk encryption status unknown.", "Data Leak", "High", "LAPTOP-HR-11", "User report", 22, "Contained", "sara", None),
    ("Phishing simulation clicked by 18% of staff", "Quarterly awareness test result above the 10% target.", "Phishing", "Low", "All staff", "Audit / review", 14, "New", "Unassigned", None),
    ("Repeated failed logins on admin portal", "300 failed logins from one external IP against the admin interface.", "Unauthorized Access", "Medium", "Admin portal", "Firewall / IDS", 9, "New", "analyst", None),
    ("Ransom note on file server share", "A text file demanding payment appeared on the shared drive of the finance department.", "Malware", "Critical", "FILESRV-01", "User report", 3, "New", "Unassigned", None),
]
NOTES = [
    ("Analysis", "Collected logs and confirmed the affected scope."),
    ("Containment", "Blocked the indicators of compromise at the firewall and mail gateway."),
    ("Eradication", "Reset credentials for affected accounts and enforced MFA."),
    ("Containment", "Isolated the host and captured a memory image for analysis."),
    ("Recovery", "Patched the affected system and verified with a follow-up scan."),
    ("Communication", "Notified the asset owner and agreed on a remediation window."),
]


def _h(n):
    return hashlib.sha256(("sentinel-demo-sample-%d" % n).encode()).hexdigest()


# title -> (MITRE tactics, TLP, [(ioc type, value, note)]).  Some indicators are shared on purpose to show correlation.
DEMO_META = {
    "Ransomware activity on HR workstation": (["Execution", "Defense Evasion", "Impact"], "RED", [("hash", _h(1), "Dropper SHA-256"), ("file", "README_DECRYPT.txt", "Ransom note"), ("ip", "45.9.148.114", "Payload download host")]),
    "Credential phishing wave targeting Finance": (["Initial Access", "Credential Access"], "AMBER", [("domain", "secure-bankportal-login.com", "Phishing domain"), ("url", "http://secure-bankportal-login.com/auth", "Credential harvesting page"), ("email", "billing@secure-bankportal-login.com", "Sender address")]),
    "Brute-force attempts on VPN gateway": (["Initial Access", "Credential Access"], "GREEN", [("ip", "185.220.101.47", "Main source of the attempts"), ("ip", "185.220.101.52", "Secondary source")]),
    "Public web server hit by HTTP flood": (["Impact"], "GREEN", [("ip", "91.240.118.12", "Top talker during the flood")]),
    "Unpatched Apache Struts instance exploited": (["Initial Access", "Execution", "Persistence"], "AMBER", [("ip", "45.9.148.114", "Exploit source"), ("file", "cmd.jsp", "Webshell found on disk")]),
    "USB storage used to copy research data": (["Collection", "Exfiltration"], "AMBER", [("file", "research_project_2026.zip", "Archive copied to USB")]),
    "Customer list found in public paste site": (["Exfiltration"], "AMBER", [("url", "https://paste.example.net/raw/Zk3x9q", "Public paste with customer e-mails")]),
    "Admin account used from unusual country": (["Initial Access", "Privilege Escalation"], "AMBER", [("ip", "185.220.101.47", "Sign-in source")]),
    "Malicious macro document opened": (["Execution", "Command and Control"], "AMBER", [("hash", _h(2), "Excel attachment"), ("domain", "update-cdn-sync.net", "C2 domain")]),
    "Shadow IT cloud storage in use": (["Exfiltration"], "GREEN", [("domain", "files.unapproved-cloud.example", "Unapproved sync service")]),
    "CEO impersonation email (BEC)": (["Initial Access"], "AMBER", [("email", "ceo.office@secure-bankportal-login.com", "Spoofed sender"), ("domain", "secure-bankportal-login.com", "Same infrastructure as the Finance phishing wave")]),
    "Outdated TLS on payment page": (["Credential Access"], "GREEN", []),
    "Port scan from internal host": (["Discovery"], "AMBER", [("ip", "10.0.4.22", "Scanning workstation")]),
    "Database backup exposed on file share": (["Collection"], "AMBER", [("file", "crm_backup_full.bak", "Unencrypted backup")]),
    "Suspicious PowerShell on domain controller": (["Execution", "Persistence", "Defense Evasion", "Command and Control"], "RED", [("domain", "update-cdn-sync.net", "Contacted by the encoded command"), ("hash", _h(3), "Dropped script")]),
    "DNS tunnelling pattern detected": (["Command and Control", "Exfiltration"], "AMBER", [("domain", "x7f3k.tunnel-dns.xyz", "High-entropy TXT queries")]),
    "Lost laptop with unencrypted disk": (["Collection"], "AMBER", []),
    "Phishing simulation clicked by 18% of staff": ([], "WHITE", []),
    "Repeated failed logins on admin portal": (["Credential Access"], "GREEN", [("ip", "185.220.101.47", "Source of 300 failed logins")]),
    "Ransom note on file server share": (["Execution", "Impact"], "RED", [("file", "HOW_TO_RECOVER.txt", "Ransom note"), ("ip", "45.9.148.114", "Seen in earlier ransomware incidents")]),
}
DEMO_EVIDENCE = {
    "Ransomware activity on HR workstation": ("edr-isolation-log.txt", "EDR isolation log (sample)\n09:12:04 mass file rename detected on HR-WS-07\n09:12:31 host isolated from network by analyst\n09:14:02 memory image captured\n"),
    "Suspicious PowerShell on domain controller": ("powershell-4104-excerpt.txt", "Script block log excerpt (sample)\nEventID 4104 on DC-01: powershell -enc <redacted>\nParent process: services.exe\n"),
}


def seed_enrich(c, iid, title, status, assignee, t0, age):
    mitre, tlp, iocs = DEMO_META.get(title, ([], "AMBER", []))
    c.execute("UPDATE incidents SET mitre=?, tlp=? WHERE id=?", (",".join(mitre), tlp, iid))
    for typ, val, note in iocs:
        c.execute("INSERT OR IGNORE INTO iocs(incident_id,type,value,note,added_by,added_at) VALUES(?,?,?,?,?,?)",
                  (iid, typ, val, note, assignee if assignee != "Unassigned" else "analyst", iso(t0 + timedelta(hours=min(2, age / 5)))))
    if title in DEMO_EVIDENCE:
        name, text = DEMO_EVIDENCE[title]
        save_evidence(c, iid, assignee if assignee != "Unassigned" else "analyst", name, text.encode(), "Demo evidence file")
    items = c.execute("SELECT id FROM checklist WHERE incident_id=? ORDER BY sort,id", (iid,)).fetchall()
    frac = {"New": 0, "Investigating": 0.4, "Contained": 0.7, "Resolved": 1, "Closed": 1}[status]
    for j, it in enumerate(items[:round(len(items) * frac)]):
        c.execute("UPDATE checklist SET done=1, done_by=?, done_at=? WHERE id=?",
                  (assignee, iso(t0 + timedelta(hours=min(age * 0.8, 1 + j * 1.2))), it["id"]))
    if status == "Closed":
        c.execute("UPDATE incidents SET root_cause=?, lessons=? WHERE id=?",
                  ("Missing patch or weak control that allowed the initial foothold.",
                   "Tune detection rules, extend monitoring to similar assets and review the response playbook.", iid))


def seed(c, user):
    users = {"analyst", "sara", "admin"}
    now = utcnow()
    for (title, desc, cat, sev, asset, src, age, status, who, res_h) in sorted(DEMO, key=lambda x: -x[6]):
        t0 = now - timedelta(hours=age)
        iid = create_incident(c, who if who in users else "analyst", dict(
            title=title, description=desc, category=cat, severity=sev, asset=asset, source=src,
            assignee="Unassigned"), t0)
        assignee = who
        if status != "New" or who != "Unassigned":
            t1 = t0 + timedelta(minutes=20)
            c.execute("UPDATE incidents SET assignee=? WHERE id=?", (assignee, iid))
            event(c, iid, "assign", f"Assigned to {dn(c, assignee)}.", "admin", iso(t1))
        last = t0
        if status in ("Investigating", "Contained", "Resolved", "Closed"):
            t = t0 + timedelta(hours=min(1, age / 10))
            c.execute("UPDATE incidents SET status='Investigating' WHERE id=?", (iid,))
            event(c, iid, "status", "Status changed to Investigating.", assignee, iso(t))
            tg, tx = NOTES[0]
            event(c, iid, "note", tx, assignee, iso(t + timedelta(minutes=35)), tag=tg)
            last = t + timedelta(minutes=35)
        if status in ("Contained", "Resolved", "Closed"):
            t = last + timedelta(hours=1.5)
            c.execute("UPDATE incidents SET status='Contained' WHERE id=?", (iid,))
            event(c, iid, "status", "Status changed to Contained.", assignee, iso(t))
            last = t
        if status in ("Resolved", "Closed"):
            t = t0 + timedelta(hours=res_h)
            c.execute("UPDATE incidents SET status='Resolved', resolved_at=? WHERE id=?", (iso(t), iid))
            tg, tx = random.choice(NOTES[1:])
            event(c, iid, "note", tx, assignee, iso(t - timedelta(minutes=30)), tag=tg)
            event(c, iid, "status", "Status changed to Resolved.", assignee, iso(t))
            last = t
        if status == "Closed":
            t = last + timedelta(hours=2)
            c.execute("UPDATE incidents SET status='Closed', closed_at=?, resolution=? WHERE id=?",
                      (iso(t), "Threat removed, root cause addressed and monitoring tuned.", iid))
            event(c, iid, "close", "Incident closed: Threat removed, root cause addressed and monitoring tuned.", assignee, iso(t))
            last = t
        touch(c, iid, iso(last))
        seed_enrich(c, iid, title, status, assignee, t0, age)
    audit(c, user, "demo.seed", f"{len(DEMO)} incidents")


# ---------------------------------------------------------------- HTTP
def bad(msg):
    return (400, {"error": msg})


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, obj=None, raw=None, ctype="application/json; charset=utf-8", headers=()):
        body = raw if raw is not None else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if TLS_ON:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; "
                             "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def err(self, code, msg):
        self.send(code, {"error": msg})

    def cookie_sid(self):
        for p in self.headers.get("Cookie", "").split(";"):
            k, _, v = p.strip().partition("=")
            if k == "sid":
                return v
        return None

    def body(self, limit=JSON_LIMIT):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            d = json.loads(self.rfile.read(min(n, limit)) or b"{}") if n else {}
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}

    def static(self, name):
        types = {".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml",
                 ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2"}
        path = os.path.join(STATIC_DIR, name)
        ext = os.path.splitext(name)[1].lower()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or ext not in types or not os.path.isfile(path):
            return self.err(404, "Not found")
        with open(path, "rb") as f:
            return self.send(200, raw=f.read(), ctype=types[ext])

    do_GET = lambda self: self.route("GET")
    do_POST = lambda self: self.route("POST")
    do_DELETE = lambda self: self.route("DELETE")

    def route(self, m):
        path = urlparse(self.path).path.rstrip("/") or "/"
        self.qs = parse_qs(urlparse(self.path).query)
        try:
            if not path.startswith("/api/"):
                if m == "GET" and path in ("/", "/index.html"):
                    with open(os.path.join(BASE, "index.html"), "rb") as f:
                        return self.send(200, raw=f.read(), ctype="text/html; charset=utf-8")
                if m == "GET" and path.startswith("/static/"):
                    return self.static(path[8:])
                if path == "/favicon.ico":
                    return self.send(204, raw=b"", ctype="image/x-icon")
                return self.err(404, "Not found")
            if m != "GET" and path != "/api/integrations/webhook" and self.headers.get("X-Requested-With") != "SOC" and not self.headers.get("Authorization", "").startswith("Bearer "):
                return self.err(403, "Missing request header")
            try:
                clen = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                clen = 0
            if m != "GET" and clen > (UPLOAD_LIMIT if path.endswith("/evidence") else JSON_LIMIT):
                self.close_connection = True      # do not try to read an oversized body
                return self.err(413, "Request is too large")
            with LOCK:
                self.api(m, path)
        except Exception as e:  # keep the server alive on bugs
            print("ERROR:", repr(e))
            try:
                self.err(500, "Internal server error")
            except Exception:
                pass

    # ---- API dispatch
    def api(self, m, path):
        d = self.body(UPLOAD_LIMIT if path.endswith("/evidence") else JSON_LIMIT) if m != "GET" else {}
        c = db()
        try:
            refresh_asset_crit(c)
            if path == "/api/health" and m == "GET":
                c.execute("SELECT 1").fetchone()
                return self.send(200, {"ok": True, "version": VERSION, "time": iso(utcnow())})
            if path == "/api/integrations/webhook" and m == "POST":
                return self.integration_webhook(c, d)
            if path == "/api/login" and m == "POST":
                return self.login(c, d)
            sid = self.cookie_sid()
            s = SESSIONS.get(sid)
            tokrow, auth_hdr = None, self.headers.get("Authorization", "")
            if (not s or s["exp"] < time.time()) and auth_hdr.startswith("Bearer "):
                tokrow = token_auth(c, auth_hdr)
                if not tokrow:
                    return self.err(401, "Invalid or expired API token")
                s = {"username": tokrow["username"], "weak": False}
            elif not s or s["exp"] < time.time():
                SESSIONS.pop(sid, None)
                return self.err(401, "Please sign in")
            row = c.execute("SELECT * FROM users WHERE username=? AND active=1", (s["username"],)).fetchone()
            if not row:
                if not tokrow:
                    SESSIONS.pop(sid, None)
                return self.err(401, "Account disabled")
            if not tokrow:
                s["exp"] = time.time() + SESSION_TTL
                s["last"] = time.time()
            u = {"username": row["username"], "full_name": row["full_name"], "role": row["role"], "email": row["email"],
                 "mfa": bool(row["totp_enabled"]), "default_password": bool(s.get("weak"))}
            if tokrow:            # API tokens never exceed analyst rights and cannot manage accounts or credentials
                u["role"] = "viewer" if tokrow["scope"] == "read" or row["role"] == "viewer" else "analyst"
                u["via_token"] = True
            role = u["role"]
            parts = path.split("/")[2:]
            if tokrow and (parts[0] in ("tokens", "sessions", "2fa") or path == "/api/password"):
                return self.err(403, "This action needs a signed-in browser session, not an API token")

            if path == "/api/me" and m == "GET":
                return self.send(200, u)
            if path == "/api/logout" and m == "POST":
                SESSIONS.pop(sid, None)
                audit(c, u["username"], "auth.logout")
                c.commit()
                return self.send(200, {"ok": True})
            if path == "/api/password" and m == "POST":
                return self.change_password(c, row, d)
            if parts[0] == "tokens":
                return self.tokens_api(c, u, parts, m, d)
            if parts[0] == "sessions":
                return self.sessions_api(c, u, sid, path, m, d)
            if parts[0] == "mentions":
                return self.mentions_api(c, u, path, m)
            if parts[0] == "2fa" and m == "POST" and len(parts) == 2:
                return self.two_factor(c, row, parts[1], d)
            if path == "/api/alerts" and m == "GET":
                return self.send(200, alerts(c))
            if path == "/api/search" and m == "GET":
                return self.send(200, search_all(c, self.qs.get("q", [""])[0]))
            if path == "/api/iocs" and m == "GET":
                return self.ioc_hub(c, u)
            if path == "/api/iocs.csv" and m == "GET":
                return self.ioc_hub(c, u, csv_out=True)
            if path == "/api/report/summary" and m == "GET":
                try:
                    days = int(self.qs.get("days", ["30"])[0])
                except ValueError:
                    days = 30
                return self.send(200, period_report(c, days if days in (7, 14, 30, 90, 365) else 30))
            if path == "/api/meta" and m == "GET":
                people = [{"username": r["username"], "full_name": r["full_name"]} for r in c.execute(
                    "SELECT username,full_name FROM users WHERE active=1 AND role IN('admin','analyst') ORDER BY full_name")]
                return self.send(200, {"categories": get_lookups(c, "category"), "severities": SEVERITIES, "statuses": STATUSES,
                                       "sources": get_lookups(c, "source"), "action_types": get_lookups(c, "action_type"),
                                       "sla_hours": get_sla(c), "people": people, "mitre": MITRE, "tlp": TLP,
                                       "ioc_types": IOC_TYPES, "version": VERSION, "asset_types": ASSET_TYPES, "criticality": CRITICALITY,
                                       "assets": [dict(r) for r in c.execute("SELECT name,type,criticality FROM assets ORDER BY name COLLATE NOCASE")]})
            if path == "/api/dashboard" and m == "GET":
                try:
                    days = int(self.qs.get("days", ["14"])[0])
                except ValueError:
                    days = 14
                return self.send(200, dashboard(c, days))
            if path == "/api/export.csv" and m == "GET":
                return self.export_csv(c, u)
            if path == "/api/assets.csv" and m == "GET":
                return self.assets_csv(c, u)
            if parts[0] == "assets":
                return self.assets(c, m, parts, d, u)
            if parts[0] == "incidents":
                return self.incidents(c, m, parts, d, u)
            # ---- admin only below
            if role != "admin":
                return self.err(403, "Administrator access required")
            if path == "/api/admin/system" and m == "GET":
                return self.send(200, system_status(c))
            if path == "/api/audit/verify" and m == "GET":
                return self.send(200, verify_audit(c))
            if path == "/api/audit" and m == "GET":
                rows = c.execute("SELECT at,username,action,detail FROM audit ORDER BY id DESC LIMIT 500").fetchall()
                return self.send(200, [dict(r) for r in rows])
            if path == "/api/audit.csv" and m == "GET":
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(["at", "username", "action", "detail", "entry_hash"])
                for r in c.execute("SELECT at,username,action,detail,hash FROM audit ORDER BY id DESC"):
                    w.writerow([csv_safe(x) for x in (r["at"], r["username"], r["action"], r["detail"], r["hash"])])
                audit(c, u["username"], "audit.export", "csv")
                c.commit()
                return self.send(200, raw=("\ufeff" + buf.getvalue()).encode("utf-8"), ctype="text/csv; charset=utf-8",
                                 headers=[("Content-Disposition", 'attachment; filename="audit-log.csv"')])
            if path == "/api/users" and m == "GET":
                rows = c.execute("SELECT username,full_name,email,role,active,created_at,last_login,totp_enabled AS mfa FROM users ORDER BY id").fetchall()
                return self.send(200, [dict(r) for r in rows])
            if path == "/api/users" and m == "POST":
                return self.create_user(c, u, d)
            if len(parts) == 3 and parts[0] == "users" and m == "POST":
                return self.user_action(c, u, parts[1], parts[2], d)
            if parts[0] == "db":
                return self.dbmgr(c, u, m, parts[1:], d)
            if path == "/api/settings/notifications" and m == "GET":
                cfg = notification_config()
                return self.send(200, {"channels": {"email": cfg["email_enabled"], "telegram": cfg["telegram_enabled"], "slack": cfg["slack_enabled"], "discord": cfg["discord_enabled"]}, "email_recipients": cfg["email_recipients"], "sla_check_seconds": cfg["sla_check_seconds"], "configuration_source": "environment variables",
                                       "webhook_configured": bool(os.environ.get("SENTINEL_WEBHOOK_TOKEN", "").strip())})
            if path == "/api/settings/notifications/test" and m == "POST":
                results = deliver_notification("Test notification", "This is a test message from SentinelDesk. If received, the channel is configured correctly.")
                audit(c, u["username"], "notifications.test", ", ".join(f"{k}={'ok' if v[0] else 'failed'}" for k,v in results.items()) or "no channels configured")
                c.commit()
                return self.send(200, {"ok": bool(results) and all(v[0] for v in results.values()), "channels": {k: {"ok": v[0], "detail": v[1]} for k,v in results.items()}, "message": "Test attempted; inspect each channel result." if results else "No notification channels configured"})
            if path == "/api/settings" and m == "GET":
                lists = {}
                for kind, (_, tbl, col) in LOOKUP_KINDS.items():
                    rows = c.execute("SELECT id,name,active FROM lookups WHERE kind=? ORDER BY sort,id", (kind,)).fetchall()
                    lists[kind] = [{"id": r["id"], "name": r["name"], "active": r["active"],
                                    "usage": c.execute(f"SELECT COUNT(*) FROM {tbl} WHERE {col}=?", (r["name"],)).fetchone()[0]} for r in rows]
                return self.send(200, {"sla": get_sla(c), "lists": lists})
            if path == "/api/settings/sla" and m == "POST":
                return self.save_sla(c, u, d)
            if parts[0] == "lookups" and m == "POST":
                try:
                    if len(parts) == 1:
                        key = db_insert(c, u["username"], "lookups", {"kind": d.get("kind"), "name": d.get("name")})
                    elif len(parts) == 3 and parts[2] == "delete":
                        db_delete(c, u["username"], "lookups", parts[1]); key = parts[1]
                    elif len(parts) == 2:
                        key = db_update(c, u["username"], "lookups", parts[1], {k: d[k] for k in ("name", "active") if k in d})
                    else:
                        return self.err(404, "Not found")
                except ValueError as e:
                    c.rollback()
                    return self.err(400, str(e))
                c.commit()
                return self.send(200, {"ok": True, "id": key})
            if path == "/api/attack_lab/status" and m == "GET":
                return self.send(200, attack_lab_status())
            if path == "/api/attack_lab/start" and m == "POST":
                ok, msg = start_attack_lab()
                if not ok:
                    return self.err(409, msg)
                audit(c, u["username"], "attack_lab.start", msg)
                c.commit()
                return self.send(200, attack_lab_status())
            if path == "/api/attack_lab/stop" and m == "POST":
                stop_attack_lab()
                audit(c, u["username"], "attack_lab.stop", "")
                c.commit()
                return self.send(200, attack_lab_status())
            if path == "/api/demo" and m == "POST":
                if c.execute("SELECT 1 FROM incidents LIMIT 1").fetchone():
                    return self.err(409, "Demo data can only be loaded into an empty system")
                random.seed(7)
                seed(c, u["username"])
                c.commit()
                return self.send(200, {"ok": True})
            self.err(404, "Not found")
        finally:
            c.close()

    # ---- auth
    def login(self, c, d):
        un, pw = str(d.get("username", "")).strip().lower()[:40], str(d.get("password", ""))
        ip_key, now = "ip:" + self.client_address[0], time.time()

        def locked(key, limit):
            n, t = FAILS.get(key, (0, 0))
            return n >= limit and now - t < 300

        def fail(key):
            n, t = FAILS.get(key, (0, 0))
            FAILS[key] = ((n if now - t < 300 else 0) + 1, now)
        if locked(un, 5) or locked(ip_key, 30):
            return self.err(429, "Too many failed attempts. Try again in 5 minutes.")
        r = c.execute("SELECT * FROM users WHERE username=?", (un,)).fetchone()
        ok = r and r["active"] and hmac.compare_digest(hash_pw(pw, r["salt"]), r["pw_hash"])
        if not ok:
            fail(un); fail(ip_key)
            audit(c, un or "?", "auth.login_failed")
            c.commit()
            return self.err(401, "Incorrect username or password")
        if r["totp_enabled"]:
            code = str(d.get("code", "")).strip()
            if not code:
                return self.send(401, {"error": "Enter the 6-digit code from your authenticator app", "mfa_required": True})
            if not totp_verify(r["totp_secret"], code, un):
                fail(un); fail(ip_key)
                audit(c, un, "auth.mfa_failed")
                c.commit()
                return self.send(401, {"error": "Invalid or already used authentication code", "mfa_required": True})
        FAILS.pop(un, None)
        for k, v in list(SESSIONS.items()):          # drop expired sessions
            if v["exp"] < now:
                SESSIONS.pop(k, None)
        sid = secrets.token_urlsafe(32)
        weak = pw == DEFAULT_PASSWORDS.get(un)
        SESSIONS[sid] = {"username": r["username"], "exp": now + SESSION_TTL, "weak": weak, "created": now, "last": now,
                         "ip": self.client_address[0], "ua": self.headers.get("User-Agent", "")[:160]}
        c.execute("UPDATE users SET last_login=? WHERE id=?", (iso(utcnow()), r["id"]))
        audit(c, un, "auth.login", "with 2FA" if r["totp_enabled"] else "")
        c.commit()
        self.send(200, {"username": r["username"], "full_name": r["full_name"], "role": r["role"]},
                  headers=[("Set-Cookie", f"sid={sid}; HttpOnly; SameSite=Strict; Path=/" + ("; Secure" if TLS_ON or self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""))])

    def two_factor(self, c, row, op, d):
        """Self-service TOTP: setup -> enable (confirm a code) -> disable (password + code)."""
        me = row["username"]
        if op == "setup":
            if row["totp_enabled"]:
                return self.err(409, "Two-factor authentication is already enabled")
            secret = new_totp_secret()
            c.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, row["id"]))
            audit(c, me, "auth.mfa_setup")
            c.commit()
            uri = f"otpauth://totp/SentinelDesk:{quote(me)}?secret={secret}&issuer=SentinelDesk&algorithm=SHA1&digits=6&period=30"
            return self.send(200, {"secret": secret, "uri": uri})
        if op == "enable":
            if row["totp_enabled"] or not row["totp_secret"]:
                return self.err(409, "Start the setup first")
            if not totp_verify(row["totp_secret"], d.get("code"), me):
                return self.err(400, "That code is not valid. Check the time on your phone and try again.")
            c.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (row["id"],))
            audit(c, me, "auth.mfa_enabled")
            c.commit()
            return self.send(200, {"ok": True})
        if op == "disable":
            if not row["totp_enabled"]:
                return self.err(409, "Two-factor authentication is not enabled")
            if not hmac.compare_digest(hash_pw(str(d.get("password", "")), row["salt"]), row["pw_hash"]) or \
                    not totp_verify(row["totp_secret"], d.get("code"), me):
                return self.err(400, "Password or code is incorrect")
            c.execute("UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?", (row["id"],))
            audit(c, me, "auth.mfa_disabled")
            c.commit()
            return self.send(200, {"ok": True})
        return self.err(404, "Not found")

    # ---- personal API tokens (created in the browser; used by scripts with "Authorization: Bearer ...")
    def tokens_api(self, c, u, parts, m, d):
        un, now = u["username"], utcnow()
        if len(parts) == 1 and m == "GET":
            rows = c.execute("SELECT id,name,prefix,scope,created_at,expires_at,last_used,revoked FROM api_tokens WHERE username=? ORDER BY id DESC", (un,)).fetchall()
            return self.send(200, [dict(r, expired=when_of(r["expires_at"]) < now) for r in rows])
        if len(parts) == 1 and m == "POST":
            name, scope = str(d.get("name", "")).strip(), str(d.get("scope", "read"))
            try:
                days = int(d.get("days", 90))
            except (TypeError, ValueError):
                days = 0
            if not name or len(name) > 60:
                return self.err(400, "Give the token a name (60 characters at most)")
            if scope not in ("read", "write") or not 1 <= days <= 365:
                return self.err(400, "Invalid scope or lifetime (1 to 365 days)")
            if scope == "write" and u["role"] not in ("admin", "analyst"):
                return self.err(403, "Your role is read-only")
            active = [r for r in c.execute("SELECT expires_at FROM api_tokens WHERE username=? AND revoked=0", (un,)) if when_of(r["expires_at"]) >= now]
            if len(active) >= 10:
                return self.err(409, "You already have 10 active tokens. Revoke one first.")
            tok = TOKEN_PREFIX + secrets.token_urlsafe(32)
            c.execute("INSERT INTO api_tokens(username,name,prefix,token_hash,scope,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
                      (un, name, tok[:12], hash_token(tok), scope, iso(now), iso(now + timedelta(days=days))))
            audit(c, un, "token.create", f"{name} ({scope}, {days} days)")
            c.commit()
            return self.send(200, {"token": tok, "prefix": tok[:12]})
        if len(parts) == 3 and parts[2] == "revoke" and m == "POST":
            t = c.execute("SELECT id,name,username FROM api_tokens WHERE id=?", (parts[1],)).fetchone() if parts[1].isdigit() else None
            if not t or (t["username"] != un and u["role"] != "admin"):
                return self.err(404, "Token not found")
            c.execute("UPDATE api_tokens SET revoked=1 WHERE id=?", (t["id"],))
            audit(c, un, "token.revoke", f"{t['name']} ({t['username']})")
            c.commit()
            return self.send(200, {"ok": True})
        return self.err(404, "Not found")

    # ---- active sessions (self-service) and @mentions
    def sessions_api(self, c, u, sid, path, m, d):
        un, now = u["username"], time.time()
        mine = [(k, v) for k, v in SESSIONS.items() if v["username"] == un and v["exp"] >= now]
        if path == "/api/sessions" and m == "GET":
            ts = lambda x: iso(datetime.fromtimestamp(x, timezone.utc))
            out = [{"id": sid_hash(k), "ip": v.get("ip", ""), "ua": v.get("ua", ""), "created": ts(v.get("created", v["exp"] - SESSION_TTL)),
                    "last": ts(v.get("last", v.get("created", v["exp"] - SESSION_TTL))), "current": k == sid} for k, v in mine]
            return self.send(200, sorted(out, key=lambda x: x["last"], reverse=True))
        if path == "/api/sessions/revoke" and m == "POST":
            target = str(d.get("id", ""))
            for k, v in mine:
                if sid_hash(k) == target:
                    if k == sid:
                        return self.err(400, "Use Sign out to end this session")
                    SESSIONS.pop(k, None)
                    audit(c, un, "auth.session_revoked", target)
                    c.commit()
                    return self.send(200, {"ok": True})
            return self.err(404, "Session not found")
        if path == "/api/sessions/revoke_others" and m == "POST":
            gone = [k for k, v in mine if k != sid]
            for k in gone:
                SESSIONS.pop(k, None)
            audit(c, un, "auth.sessions_revoked", f"{len(gone)} other sessions")
            c.commit()
            return self.send(200, {"ok": True, "revoked": len(gone)})
        return self.err(404, "Not found")

    def mentions_api(self, c, u, path, m):
        un = u["username"]
        if path == "/api/mentions" and m == "GET":
            rows = c.execute("""SELECT x.id,x.incident_id,x.by_user,x.excerpt,x.at,x.read,i.title FROM mentions x
                                JOIN incidents i ON i.id=x.incident_id WHERE x.username=? ORDER BY x.id DESC LIMIT 30""", (un,)).fetchall()
            unread = c.execute("SELECT COUNT(*) FROM mentions WHERE username=? AND read=0", (un,)).fetchone()[0]
            return self.send(200, {"unread": unread, "items": [dict(r) for r in rows]})
        if path == "/api/mentions/read" and m == "POST":
            c.execute("UPDATE mentions SET read=1 WHERE username=?", (un,))
            c.commit()
            return self.send(200, {"ok": True})
        return self.err(404, "Not found")

    def ioc_hub(self, c, u, csv_out=False):
        groups = {}
        for r in c.execute("""SELECT x.type,x.value,x.note,x.incident_id,x.added_at,i.title,i.severity,i.status
                              FROM iocs x JOIN incidents i ON i.id=x.incident_id ORDER BY x.added_at"""):
            g = groups.setdefault((r["type"], r["value"]), {"type": r["type"], "value": r["value"], "incidents": [],
                                                           "first_seen": r["added_at"], "last_seen": r["added_at"], "notes": []})
            g["incidents"].append({"id": r["incident_id"], "title": r["title"], "severity": r["severity"], "status": r["status"]})
            g["last_seen"] = max(g["last_seen"], r["added_at"])
            if r["note"] and r["note"] not in g["notes"]:
                g["notes"].append(r["note"])
        out = sorted(groups.values(), key=lambda g: (-len(g["incidents"]), -(parse(g["last_seen"]).timestamp())))
        for g in out:
            g["count"] = len(g["incidents"])
        if not csv_out:
            return self.send(200, out[:1000])
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "incident_count", "incidents", "first_seen", "last_seen", "notes"])
        for g in out:
            w.writerow([csv_safe(g["type"]), csv_safe(g["value"]), g["count"], " ".join(i["id"] for i in g["incidents"]),
                        g["first_seen"], g["last_seen"], csv_safe("; ".join(g["notes"]))])
        audit(c, u["username"], "ioc.export", "csv")
        c.commit()
        return self.send(200, raw=("\ufeff" + buf.getvalue()).encode("utf-8"), ctype="text/csv; charset=utf-8",
                         headers=[("Content-Disposition", 'attachment; filename="indicators.csv"')])

    def change_password(self, c, row, d):
        cur, new = str(d.get("current", "")), str(d.get("new", ""))
        if not hmac.compare_digest(hash_pw(cur, row["salt"]), row["pw_hash"]):
            return self.err(400, "Current password is incorrect")
        bad = password_error(c, row["username"], new)
        if bad:
            return self.err(400, "New " + bad[0].lower() + bad[1:] if bad.startswith("Password needs") else bad)
        remember_password(c, row["username"])
        salt = secrets.token_hex(16)
        c.execute("UPDATE users SET salt=?, pw_hash=? WHERE id=?", (salt, hash_pw(new, salt), row["id"]))
        audit(c, row["username"], "auth.password_change")
        for token, session in list(SESSIONS.items()):
            if session.get("username") == row["username"]:
                SESSIONS.pop(token, None)
        c.commit()
        self.send(200, {"ok": True})

    # ---- authenticated external alert ingestion (SIEM / EDR / IDS)
    def integration_webhook(self, c, d):
        """Accept a normalized JSON alert from a trusted integration.

        Configure SENTINEL_WEBHOOK_TOKEN outside source control. This endpoint intentionally
        requires a bearer token and deduplicates alerts by provider + external_id.
        """
        configured = os.environ.get("SENTINEL_WEBHOOK_TOKEN", "").strip()
        supplied = self.headers.get("Authorization", "")
        expected = "Bearer " + configured if configured else ""
        if not configured or not hmac.compare_digest(supplied, expected):
            audit(c, "integration", "webhook.rejected", "missing/invalid token")
            c.commit()
            return self.err(401, "Integration token is not configured or is invalid")
        provider = str(d.get("provider", "external")).strip()[:60]
        external_id = str(d.get("external_id", "")).strip()[:200]
        title = str(d.get("title", "")).strip()[:120]
        description = str(d.get("description", "")).strip()[:4000]
        asset = str(d.get("asset", "Unknown asset")).strip()[:200]
        severity_map = {"info": "Low", "low": "Low", "medium": "Medium", "warning": "Medium",
                        "high": "High", "error": "High", "critical": "Critical", "fatal": "Critical"}
        severity = severity_map.get(str(d.get("severity", "medium")).lower(), "Medium")
        category = str(d.get("category", "Other"))
        source = str(d.get("source", "SIEM alert"))
        if not external_id or not title or not description:
            return self.err(400, "provider, external_id, title and description are required")
        if category not in get_lookups(c, "category"):
            category = "Other" if "Other" in get_lookups(c, "category") else get_lookups(c, "category")[0]
        if source not in get_lookups(c, "source"):
            source = "SIEM alert" if "SIEM alert" in get_lookups(c, "source") else get_lookups(c, "source")[0]
        payload_hash = hashlib.sha256(json.dumps(d, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        prior = c.execute("SELECT incident_id FROM webhook_events WHERE provider=? AND external_id=?", (provider, external_id)).fetchone()
        if prior:
            return self.send(200, {"ok": True, "duplicate": True, "incident_id": prior["incident_id"]})
        username = "integration"
        values = {"title": title, "description": description, "category": category, "severity": severity,
                  "asset": asset or "Unknown asset", "source": source, "assignee": "Unassigned"}
        iid = create_incident(c, username, values)
        event(c, iid, "note", f"Automatically ingested from {provider}; external alert ID: {external_id}.", username)
        tactics = [m for m in (d.get("mitre") if isinstance(d.get("mitre"), list) else []) if m in MITRE]
        tlp = str(d.get("tlp", "AMBER")).upper()
        c.execute("UPDATE incidents SET mitre=?, tlp=? WHERE id=?", (",".join(tactics), tlp if tlp in TLP else "AMBER", iid))
        for ind in (d.get("iocs") if isinstance(d.get("iocs"), list) else [])[:50]:
            try:
                typ, val = (clean_ioc(ind.get("type"), ind.get("value")) if isinstance(ind, dict) else clean_ioc("", ind))
                c.execute("INSERT OR IGNORE INTO iocs(incident_id,type,value,note,added_by,added_at) VALUES(?,?,?,?,?,?)",
                          (iid, typ, val, f"From {provider}", username, iso(utcnow())))
            except ValueError:
                continue
        c.execute("INSERT INTO webhook_events(provider,external_id,incident_id,received_at,payload_sha256) VALUES(?,?,?,?,?)",
                  (provider, external_id, iid, iso(utcnow()), payload_hash))
        audit(c, username, "webhook.incident_created", f"{provider}:{external_id} -> {iid}")
        c.commit()
        threading.Thread(target=notify_once, args=("incident-created:" + iid, f"New {severity} incident", f"Incident: {iid} — {title}\nSeverity: {severity}\nAsset: {asset}\nSource: {provider}\nDescription: {description}"), daemon=True).start()
        return self.send(201, {"ok": True, "duplicate": False, "incident_id": iid})

    # ---- users (admin)
    def create_user(self, c, u, d):
        un = re.sub(r"[^a-z0-9._-]", "", str(d.get("username", "")).strip().lower())[:30]
        fn, role, pw = str(d.get("full_name", "")).strip()[:60], str(d.get("role", "")), str(d.get("password", ""))
        email = str(d.get("email", "")).strip()[:80]
        if len(un) < 3 or not fn or role not in ROLES:
            return self.err(400, "Enter a username (3+ characters), full name and role")
        bad = password_error(c, un, pw)
        if bad:
            return self.err(400, bad)
        if c.execute("SELECT 1 FROM users WHERE username=?", (un,)).fetchone():
            return self.err(409, "That username already exists")
        add_user(c, un, fn, role, pw, email)
        audit(c, u["username"], "user.create", f"{un} ({role})")
        c.commit()
        self.send(200, {"ok": True})

    def user_action(self, c, u, target, op, d):
        t = c.execute("SELECT * FROM users WHERE username=?", (target,)).fetchone()
        if not t:
            return self.err(404, "User not found")
        if op == "toggle":
            if target == u["username"]:
                return self.err(400, "You cannot disable your own account")
            new = 0 if t["active"] else 1
            c.execute("UPDATE users SET active=? WHERE id=?", (new, t["id"]))
            audit(c, u["username"], "user.enable" if new else "user.disable", target)
        elif op == "mfa_reset":
            c.execute("UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?", (t["id"],))
            audit(c, u["username"], "user.mfa_reset", target)
        elif op == "signout":
            gone = [k for k, v in SESSIONS.items() if v["username"] == target]
            for k in gone:
                SESSIONS.pop(k, None)
            c.execute("UPDATE api_tokens SET revoked=1 WHERE username=?", (target,))
            audit(c, u["username"], "user.signout", f"{target} ({len(gone)} sessions, API tokens revoked)")
        elif op == "role":
            role = str(d.get("role", ""))
            if role not in ROLES or target == u["username"]:
                return self.err(400, "Invalid role change")
            c.execute("UPDATE users SET role=? WHERE id=?", (role, t["id"]))
            audit(c, u["username"], "user.role", f"{target} -> {role}")
        elif op == "password":
            pw = str(d.get("password", ""))
            bad = password_error(c, target, pw)
            if bad:
                return self.err(400, bad)
            remember_password(c, target)
            salt = secrets.token_hex(16)
            c.execute("UPDATE users SET salt=?, pw_hash=? WHERE id=?", (salt, hash_pw(pw, salt), t["id"]))
            audit(c, u["username"], "user.password_reset", target)
        else:
            return self.err(404, "Not found")
        c.commit()
        self.send(200, {"ok": True})

    # ---- settings / database manager (admin)
    def save_sla(self, c, u, d):
        hrs = d.get("hours") or {}
        clean = {}
        for sev in SEVERITIES:
            try:
                clean[sev] = int(hrs.get(sev))
            except (TypeError, ValueError):
                return self.err(400, f"Enter whole hours for {sev}")
            if not 1 <= clean[sev] <= 720:
                return self.err(400, "Hours must be between 1 and 720")
        for sev, h in clean.items():
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("sla_" + sev, str(h)))
        n = 0
        if d.get("apply_open"):
            for r in c.execute("SELECT id,severity,created_at FROM incidents WHERE status IN('New','Investigating','Contained')").fetchall():
                c.execute("UPDATE incidents SET due_at=? WHERE id=?", (iso(parse(r["created_at"]) + timedelta(hours=clean[r["severity"]])), r["id"]))
                n += 1
        audit(c, u["username"], "settings.sla", ", ".join(f"{k}={v}h" for k, v in clean.items()) + (f"; recalculated {n} open" if n else ""))
        c.commit()
        self.send(200, {"ok": True, "recalculated": n})

    def dbmgr(self, c, u, m, parts, d):
        me, qs, sub = u["username"], self.qs, (parts[0] if parts else "")
        try:
            if sub == "tables" and m == "GET":
                out = []
                for name, cfg in TABLES.items():
                    out.append({"name": name, "rows": c.execute(f"SELECT COUNT(*) FROM {qid(name)}").fetchone()[0], "pk": cfg["pk"],
                                "readonly": bool(cfg.get("readonly")), "no_insert": bool(cfg.get("no_insert") or cfg.get("readonly")),
                                "no_delete": bool(cfg.get("no_delete") or cfg.get("readonly")), "columns": tbl_cols(c, name)})
                return self.send(200, {"tables": out, "choices": db_choices(c)})
            if sub == "rows" and m == "GET":
                name = qs.get("table", [""])[0]
                if name not in TABLES:
                    return self.err(400, "Unknown table")
                names = [x["name"] for x in tbl_cols(c, name)]
                q = qs.get("q", [""])[0].strip()
                try:
                    page = max(1, int(qs.get("page", ["1"])[0]))
                except ValueError:
                    page = 1
                sort = qs.get("sort", [""])[0]
                sort = sort if sort in names else TABLES[name]["pk"]
                direction = "ASC" if qs.get("dir", ["desc"])[0] == "asc" else "DESC"
                where, params = "", []
                if q:
                    where = " WHERE " + " OR ".join(f"CAST({qid(n)} AS TEXT) LIKE ?" for n in names)
                    params = [f"%{q}%"] * len(names)
                total = c.execute(f"SELECT COUNT(*) FROM {qid(name)}{where}", params).fetchone()[0]
                rows = c.execute(f"SELECT {','.join(qid(n) for n in names)} FROM {qid(name)}{where} ORDER BY {qid(sort)} {direction} LIMIT ? OFFSET ?",
                                 params + [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
                return self.send(200, {"rows": [dict(r) for r in rows], "total": total, "page": page, "page_size": PAGE_SIZE})
            if sub == "row" and m == "POST":
                name, op = d.get("table"), d.get("op")
                if name not in TABLES:
                    return self.err(400, "Unknown table")
                if op == "insert":
                    key = db_insert(c, me, name, d.get("values") or {})
                elif op == "update":
                    key = db_update(c, me, name, d.get("pk"), d.get("values") or {})
                elif op == "delete":
                    db_delete(c, me, name, d.get("pk")); key = d.get("pk")
                else:
                    return self.err(400, "Unknown operation")
                c.commit()
                return self.send(200, {"ok": True, "pk": key})
            if sub == "query" and m == "POST":
                res = run_query(str(d.get("sql", "")))
                audit(c, me, "db.query", str(d.get("sql", ""))[:200])
                c.commit()
                return self.send(200, res)
            if sub == "export" and m == "GET":
                name = qs.get("table", [""])[0]
                if name not in TABLES:
                    return self.err(400, "Unknown table")
                names = [x["name"] for x in tbl_cols(c, name)]
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(names)
                for r in c.execute(f"SELECT {','.join(qid(n) for n in names)} FROM {qid(name)}"):
                    w.writerow(["'" + str(x) if isinstance(x, str) and x[:1] in "=+-@" else ("" if x is None else x) for x in r])
                audit(c, me, "db.export", name)
                c.commit()
                return self.send(200, raw=("\ufeff" + buf.getvalue()).encode("utf-8"), ctype="text/csv; charset=utf-8",
                                 headers=[("Content-Disposition", f'attachment; filename="{name}.csv"')])
            if sub == "backups":
                if m == "GET" and len(parts) == 1:
                    return self.send(200, {"backups": list_backups(), "database": os.path.basename(DB),
                                           "size": os.path.getsize(DB), "folder": BACKUP_DIR})
                if m == "POST" and len(parts) == 1:
                    name = make_backup("manual")
                    audit(c, me, "db.backup", name)
                    c.commit()
                    return self.send(200, {"ok": True, "name": name})
                if m == "POST" and len(parts) == 3 and parts[2] == "restore" and BACKUP_RE.match(parts[1]):
                    if str(d.get("confirm", "")) != parts[1]:
                        return self.err(400, "Confirmation does not match the backup name")
                    safety = restore_backup(parts[1])
                    c.close()
                    c2 = db()
                    audit(c2, me, "db.restore", f"{parts[1]} (safety copy: {safety})")
                    c2.commit()
                    c2.close()
                    return self.send(200, {"ok": True, "safety": safety})
                if m == "GET" and len(parts) == 2 and BACKUP_RE.match(parts[1]):
                    p = os.path.join(BACKUP_DIR, parts[1])
                    if not os.path.isfile(p):
                        return self.err(404, "Backup not found")
                    with open(p, "rb") as f:
                        data = f.read()
                    audit(c, me, "db.backup_download", parts[1])
                    c.commit()
                    return self.send(200, raw=data, ctype="application/octet-stream",
                                     headers=[("Content-Disposition", f'attachment; filename="{parts[1]}"')])
            return self.err(404, "Not found")
        except ValueError as e:
            c.rollback()
            return self.err(400, str(e))

    # ---- asset inventory
    def asset_rows(self, c):
        out = []
        for a in c.execute("SELECT * FROM assets ORDER BY name COLLATE NOCASE"):
            x = dict(a)
            inc = c.execute("SELECT severity,status FROM incidents WHERE asset=? COLLATE NOCASE", (a["name"],)).fetchall()
            op = [i for i in inc if i["status"] in OPEN_STATUSES]
            x["incidents"], x["open_incidents"] = len(inc), len(op)
            x["open_risk"] = max([risk_of(i["severity"], a["name"])[0] for i in op], default=0)
            out.append(x)
        return out

    def assets_csv(self, c, u):
        buf = io.StringIO()
        w = csv.writer(buf)
        cols = ["name", "type", "criticality", "owner", "department", "address", "incidents", "open_incidents", "notes"]
        w.writerow(cols)
        for x in self.asset_rows(c):
            w.writerow([csv_safe(x[k]) for k in cols])
        audit(c, u["username"], "assets.export", "csv")
        c.commit()
        return self.send(200, raw=("\ufeff" + buf.getvalue()).encode("utf-8"), ctype="text/csv; charset=utf-8",
                         headers=[("Content-Disposition", 'attachment; filename="assets.csv"')])

    def assets(self, c, m, parts, d, u):
        un, role = u["username"], u["role"]
        if len(parts) == 1 and m == "GET":
            return self.send(200, self.asset_rows(c))
        if role not in ("admin", "analyst"):
            return self.err(403, "Your role is read-only")

        def fields():
            v = {k: str(d.get(k, "")).strip() for k in ("name", "type", "owner", "department", "address", "criticality", "notes")}
            v["type"], v["criticality"] = v["type"] or "Other", v["criticality"] or "Medium"
            if not v["name"] or len(v["name"]) > 80:
                raise ValueError("Asset name is required (80 characters at most)")
            if v["type"] not in ASSET_TYPES or v["criticality"] not in CRITICALITY:
                raise ValueError("Invalid asset type or criticality")
            if any(len(v[k]) > 200 for k in ("owner", "department", "address")) or len(v["notes"]) > 1000:
                raise ValueError("A field is too long")
            return v
        if len(parts) == 1 and m == "POST":
            try:
                v = fields()
            except ValueError as e:
                return self.err(400, str(e))
            if c.execute("SELECT 1 FROM assets WHERE name=?", (v["name"],)).fetchone():
                return self.err(409, "An asset with this name already exists")
            c.execute("INSERT INTO assets(name,type,owner,department,address,criticality,notes,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                      (v["name"], v["type"], v["owner"], v["department"], v["address"], v["criticality"], v["notes"], un, iso(utcnow())))
            audit(c, un, "asset.create", f"{v['name']} ({v['criticality']})")
            c.commit()
            return self.send(200, {"ok": True})
        try:
            aid = int(parts[1])
        except ValueError:
            return self.err(404, "Asset not found")
        a = c.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        if not a:
            return self.err(404, "Asset not found")
        if len(parts) == 3 and parts[2] == "update" and m == "POST":
            try:
                v = fields()
            except ValueError as e:
                return self.err(400, str(e))
            if c.execute("SELECT 1 FROM assets WHERE name=? AND id!=?", (v["name"], aid)).fetchone():
                return self.err(409, "An asset with this name already exists")
            c.execute("UPDATE assets SET name=?,type=?,owner=?,department=?,address=?,criticality=?,notes=? WHERE id=?",
                      (v["name"], v["type"], v["owner"], v["department"], v["address"], v["criticality"], v["notes"], aid))
            if v["name"] != a["name"]:                    # keep incidents linked to the renamed asset
                c.execute("UPDATE incidents SET asset=? WHERE asset=? COLLATE NOCASE", (v["name"], a["name"]))
            note = f"{a['name']}: criticality {a['criticality']} -> {v['criticality']}" if v["criticality"] != a["criticality"] else a["name"]
            audit(c, un, "asset.update", note + (f" (renamed to {v['name']})" if v["name"] != a["name"] else ""))
            c.commit()
            return self.send(200, {"ok": True})
        if len(parts) == 2 and m == "DELETE":
            if role != "admin":
                return self.err(403, "Only administrators can delete assets")
            c.execute("DELETE FROM assets WHERE id=?", (aid,))
            audit(c, un, "asset.delete", a["name"])
            c.commit()
            return self.send(200, {"ok": True})
        return self.err(405, "Method not allowed")

    # ---- incidents
    def export_csv(self, c, u):
        buf = io.StringIO()
        w = csv.writer(buf)
        cols = ["id", "title", "category", "severity", "status", "tlp", "asset", "source", "assignee", "reporter",
                "created_at", "due_at", "resolved_at", "closed_at", "sla", "mitre"]
        w.writerow(cols)
        for r in c.execute("SELECT * FROM incidents ORDER BY created_at DESC"):
            s_ = inc_summary(r)
            s_["mitre"] = "; ".join(s_["mitre"])
            w.writerow([csv_safe(s_[k]) for k in cols])
        audit(c, u["username"], "incident.export", "csv")
        c.commit()
        self.send(200, raw=("\ufeff" + buf.getvalue()).encode("utf-8"), ctype="text/csv; charset=utf-8",
                  headers=[("Content-Disposition", 'attachment; filename="incidents.csv"')])

    def evidence_download(self, c, u, r, eid):
        e = c.execute("SELECT * FROM evidence WHERE id=? AND incident_id=?", (eid, r["id"])).fetchone() if str(eid).isdigit() else None
        if not e:
            return self.err(404, "Evidence not found")
        try:
            with open(os.path.join(EVIDENCE_DIR, os.path.basename(e["stored_name"])), "rb") as f:
                data = f.read()
        except OSError:
            return self.err(404, "The stored file is missing")
        if hashlib.sha256(data).hexdigest() != e["sha256"]:
            audit(c, u["username"], "evidence.integrity_failure", f"{r['id']}: {e['filename']}")
            c.commit()
            return self.err(409, "Integrity check failed: the stored file no longer matches its SHA-256 hash")
        audit(c, u["username"], "evidence.download", f"{r['id']}: {e['filename']}")
        c.commit()
        ascii_name = e["filename"].encode("ascii", "replace").decode().replace("?", "_").replace('"', "")
        return self.send(200, raw=data, ctype="application/octet-stream", headers=[
            ("Content-Disposition", f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(e['filename'])}"),
            ("X-Evidence-SHA256", e["sha256"])])

    def bulk(self, c, u, d):
        ids, op, val = d.get("ids"), d.get("op"), str(d.get("value", "")).strip()
        if not isinstance(ids, list) or not ids or len(ids) > 200 or not all(isinstance(i, str) for i in ids):
            return self.err(400, "Select between 1 and 200 incidents")
        if (op == "status" and val not in STATUSES[:4]) or (op == "severity" and val not in SEVERITIES) or \
                (op == "assign" and not valid_assignee(c, val)) or op not in ("status", "severity", "assign"):
            return self.err(400, "Invalid bulk action")
        done = skipped = 0
        for iid in ids:
            r = c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
            if not r or r["status"] == "Closed":
                skipped += 1
                continue
            if op == "status" and r["status"] != val:
                do_status(c, r, val, u["username"])
            elif op == "severity" and r["severity"] != val:
                do_severity(c, r, val, u["username"])
            elif op == "assign" and r["assignee"] != val:
                do_assign(c, r, val, u["username"])
            else:
                skipped += 1
                continue
            touch(c, iid)
            done += 1
        audit(c, u["username"], "incident.bulk", f"{op}={val}: {done} updated, {skipped} skipped")
        c.commit()
        return self.send(200, {"ok": True, "updated": done, "skipped": skipped})

    def import_template(self, c):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["title", "description", "category", "severity", "asset", "source", "assignee", "tlp", "created_at"])
        cats, srcs = get_lookups(c, "category"), get_lookups(c, "source")
        w.writerow(["Suspicious login from a new country", "Impossible-travel alert for a finance account", cats[0] if cats else "Other", "Medium",
                    "Mail gateway", srcs[0] if srcs else "Other", "Unassigned", "AMBER", "2026-01-15T09:30:00Z"])
        return self.send(200, raw=("\ufeff" + buf.getvalue()).encode("utf-8"), ctype="text/csv; charset=utf-8",
                         headers=[("Content-Disposition", 'attachment; filename="incident-import-template.csv"')])

    def import_incidents(self, c, u, d):
        """Validate (dry run) and import incidents from CSV. Nothing is imported if any row has an error; duplicates are skipped."""
        un = u["username"]
        text = str(d.get("csv", "")).lstrip("\ufeff")
        dry = d.get("dry_run", True) is not False
        if not text.strip() or len(text) > 400000:
            return self.err(400, "Provide CSV text (400 KB at most)")
        try:
            reader = csv.DictReader(io.StringIO(text))
            reader.fieldnames = [(n or "").strip().lower() for n in (reader.fieldnames or [])]
            rows = []
            for r in reader:
                rows.append(r)
                if len(rows) > 500:
                    return self.err(400, "Import at most 500 rows at a time")
        except csv.Error:
            return self.err(400, "The file is not valid CSV")
        missing = [x for x in ("title", "category", "severity", "asset") if x not in (reader.fieldnames or [])]
        if missing:
            return self.err(400, "Missing column(s): " + ", ".join(missing))
        canon = lambda lst: {x.lower(): x for x in lst}
        cats, srcs, sevs = canon(get_lookups(c, "category")), canon(get_lookups(c, "source")), canon(SEVERITIES)
        people = {r["username"].lower(): r["username"] for r in c.execute("SELECT username FROM users WHERE active=1 AND role IN('admin','analyst')")}
        assets = {r["name"].lower(): r["name"] for r in c.execute("SELECT name FROM assets")}
        seen = {(r["title"].strip().lower(), r["asset"].strip().lower()) for r in c.execute("SELECT title,asset FROM incidents")}
        good, errors, skipped = [], [], 0
        for n, r in enumerate(rows, start=2):
            g = lambda k: (r.get(k) or "").strip()
            title, asset = g("title"), g("asset")
            if not (title or asset or g("category")):
                continue
            err, when = None, None
            if not title or len(title) > 120:
                err = "Title is required (120 characters at most)"
            elif not asset or len(asset) > 200:
                err = "Affected asset is required"
            elif g("category").lower() not in cats:
                err = f"Unknown category '{g('category')}'"
            elif g("severity").lower() not in sevs:
                err = f"Unknown severity '{g('severity')}'"
            elif g("source") and g("source").lower() not in srcs:
                err = f"Unknown source '{g('source')}'"
            elif g("assignee") and g("assignee").lower() not in people and g("assignee").lower() != "unassigned":
                err = f"Unknown assignee '{g('assignee')}'"
            elif g("tlp") and g("tlp").upper() not in TLP:
                err = f"Invalid TLP '{g('tlp')}'"
            elif len(g("description")) > 4000:
                err = "Description is too long (4000 characters at most)"
            elif g("created_at"):
                try:
                    when = when_of(g("created_at"))
                    if when > utcnow() + timedelta(minutes=5):
                        err = "created_at is in the future"
                except ValueError:
                    err = "created_at must look like 2026-01-15 or 2026-01-15T09:30:00Z"
            if err:
                errors.append({"row": n, "error": err})
                continue
            key = (title.lower(), asset.lower())
            if key in seen:
                skipped += 1
                continue
            seen.add(key)
            assignee = people.get(g("assignee").lower(), "Unassigned")
            good.append({"when": when, "tlp": (g("tlp") or "AMBER").upper(), "v": {
                "title": title, "description": g("description") or "Imported from CSV.", "category": cats[g("category").lower()],
                "severity": sevs[g("severity").lower()], "asset": assets.get(asset.lower(), asset),
                "source": srcs.get(g("source").lower()) or srcs.get("other") or next(iter(srcs.values()), "Other"), "assignee": assignee}})
        result = {"total": len(rows), "valid": len(good), "skipped_duplicates": skipped, "errors": errors[:50], "error_count": len(errors),
                  "dry_run": dry, "created": 0}
        if dry or errors or not good:
            return self.send(200, result)
        for v in good:
            iid = create_incident(c, un, v["v"], v["when"])
            c.execute("UPDATE incidents SET tlp=? WHERE id=?", (v["tlp"], iid))
            if v["v"]["assignee"] != "Unassigned":
                event(c, iid, "assign", f"Assigned to {dn(c, v['v']['assignee'])}.", un)
        audit(c, un, "incident.import", f"{len(good)} incidents from CSV ({skipped} duplicates skipped)")
        c.commit()
        result["created"] = len(good)
        return self.send(200, result)

    def incidents(self, c, m, parts, d, u):
        un, role = u["username"], u["role"]
        can_write = role in ("admin", "analyst")
        if len(parts) == 1:
            if m == "GET":
                return self.send(200, [inc_summary(r) for r in c.execute(LIST_SQL)])
            if m == "POST":
                if not can_write:
                    return self.err(403, "Your role is read-only")
                v = {k: str(d.get(k, "")).strip() for k in ("title", "description", "category", "severity", "asset", "source", "assignee")}
                v["assignee"] = v["assignee"] or "Unassigned"
                if not (v["title"] and v["description"] and v["asset"]) or len(v["title"]) > 120 or len(v["description"]) > 4000:
                    return self.err(400, "Title, description and affected asset are required")
                if v["category"] not in get_lookups(c, "category") or v["severity"] not in SEVERITIES or v["source"] not in get_lookups(c, "source"):
                    return self.err(400, "Invalid category, severity or source")
                if not valid_assignee(c, v["assignee"]):
                    return self.err(400, "Unknown assignee")
                tlp = str(d.get("tlp", "AMBER")).upper()
                tactics = d.get("mitre") if isinstance(d.get("mitre"), list) else []
                if tlp not in TLP or any(x not in MITRE for x in tactics):
                    return self.err(400, "Invalid TLP marking or MITRE tactic")
                reg = c.execute("SELECT name FROM assets WHERE name=?", (v["asset"],)).fetchone()
                if reg:
                    v["asset"] = reg["name"]
                iid = create_incident(c, un, v)
                c.execute("UPDATE incidents SET tlp=?, mitre=? WHERE id=?", (tlp, ",".join(x for x in MITRE if x in tactics), iid))
                if v["assignee"] != "Unassigned":
                    event(c, iid, "assign", f"Assigned to {dn(c, v['assignee'])}.", un)
                c.commit()
                threading.Thread(target=notify_once, args=("incident-created:" + iid, f"New {v['severity']} incident", f"Incident: {iid} — {v['title']}\nSeverity: {v['severity']}\nAsset: {v['asset']}\nSource: {v['source']}\nReporter: {un}\nDescription: {v['description']}"), daemon=True).start()
                return self.send(200, {"id": iid})
            return self.err(405, "Method not allowed")
        if parts[1] == "import-template.csv" and m == "GET":
            return self.import_template(c)
        if parts[1] == "import" and m == "POST":
            return self.import_incidents(c, u, d) if can_write else self.err(403, "Your role is read-only")
        if parts[1] == "bulk" and m == "POST":
            return self.bulk(c, u, d) if can_write else self.err(403, "Your role is read-only")
        r = c.execute("SELECT * FROM incidents WHERE id=?", (parts[1],)).fetchone()
        if not r:
            return self.err(404, "Incident not found")
        iid = r["id"]
        if len(parts) == 2:
            if m == "GET":
                return self.send(200, inc_detail(c, r))
            if m == "DELETE":
                if role != "admin":
                    return self.err(403, "Only administrators can delete incidents")
                purge_evidence_files(c, iid)
                c.execute("DELETE FROM incidents WHERE id=?", (iid,))
                audit(c, un, "incident.delete", iid)
                c.commit()
                return self.send(200, {"ok": True})
            return self.err(405, "Method not allowed")
        if len(parts) == 4 and parts[2] == "evidence" and m == "GET":
            return self.evidence_download(c, u, r, parts[3])
        if m != "POST" or len(parts) not in (3, 4, 5):
            return self.err(405, "Method not allowed")
        if not can_write:
            return self.err(403, "Your role is read-only")
        op, result = parts[2], {"ok": True}
        if op == "reopen":
            if r["status"] != "Closed":
                return self.err(409, "Only closed incidents can be reopened")
            c.execute("UPDATE incidents SET status='Investigating', closed_at=NULL, resolved_at=NULL WHERE id=?", (iid,))
            event(c, iid, "status", "Incident reopened.", un)
            audit(c, un, "incident.reopen", iid)
        elif op == "comment":                                   # discussion between analysts; allowed on closed incidents too
            text = str(d.get("text", "")).strip()
            if not text or len(text) > 2000:
                return self.err(400, "Write a comment (up to 2000 characters)")
            event(c, iid, "comment", text, un)
            names = find_mentions(c, text, un)
            for n in names:
                c.execute("INSERT INTO mentions(incident_id,username,by_user,excerpt,at) VALUES(?,?,?,?,?)", (iid, n, un, text[:160], iso(utcnow())))
            result["mentioned"] = names
            audit(c, un, "incident.comment", iid)
        else:
            if r["status"] == "Closed":
                return self.err(409, "This incident is closed. Reopen it to make changes.")
            if op == "notes":
                text = str(d.get("text", "")).strip()
                if not text or len(text) > 2000:
                    return self.err(400, "Write a note (up to 2000 characters)")
                tag = str(d.get("tag", "Other"))
                if tag not in get_lookups(c, "action_type"):
                    return self.err(400, "Invalid action type")
                event(c, iid, "note", text, un, tag=tag)
                if r["status"] == "New":
                    c.execute("UPDATE incidents SET status='Investigating' WHERE id=?", (iid,))
                    event(c, iid, "status", "Status changed to Investigating.", un)
                audit(c, un, "incident.note", iid)
            elif op == "status":
                st = d.get("status")
                if st not in STATUSES[:4]:
                    return self.err(400, "Invalid status")
                do_status(c, r, st, un)
            elif op == "assign":
                a = str(d.get("assignee", "")).strip()
                if not valid_assignee(c, a):
                    return self.err(400, "Unknown assignee")
                do_assign(c, r, a, un)
            elif op == "severity":
                sv = d.get("severity")
                if sv not in SEVERITIES:
                    return self.err(400, "Invalid severity")
                do_severity(c, r, sv, un)
            elif op == "edit":
                new, changed = {}, []
                for k, lim in (("title", 120), ("description", 4000), ("asset", 200)):
                    if k in d:
                        val = str(d[k]).strip()
                        if not val or len(val) > lim:
                            return self.err(400, "Title, description and affected asset cannot be empty or too long")
                        if val != r[k]:
                            new[k] = val
                            changed.append(k)
                if not new:
                    return self.err(400, "Nothing was changed")
                c.execute(f"UPDATE incidents SET {','.join(k + '=?' for k in new)} WHERE id=?", list(new.values()) + [iid])
                event(c, iid, "edit", "Details edited: " + ", ".join(changed) + ".", un)
                audit(c, un, "incident.edit", f"{iid}: {', '.join(changed)}")
            elif op == "classify":
                tactics = d.get("mitre") if isinstance(d.get("mitre"), list) else mitre_list(r["mitre"])
                tlp = str(d.get("tlp", r["tlp"])).upper()
                if tlp not in TLP or any(x not in MITRE for x in tactics):
                    return self.err(400, "Invalid TLP marking or MITRE tactic")
                ordered = [x for x in MITRE if x in tactics]
                c.execute("UPDATE incidents SET mitre=?, tlp=? WHERE id=?", (",".join(ordered), tlp, iid))
                event(c, iid, "classify", f"Classification updated: TLP:{tlp}; tactics: {', '.join(ordered) or 'none'}.", un)
                audit(c, un, "incident.classify", f"{iid}: TLP:{tlp}")
            elif op == "iocs":
                if len(parts) == 3:
                    try:
                        typ, val = clean_ioc(d.get("type"), d.get("value"))
                    except ValueError as e:
                        return self.err(400, str(e))
                    if c.execute("SELECT COUNT(*) FROM iocs WHERE incident_id=?", (iid,)).fetchone()[0] >= 500:
                        return self.err(400, "Too many indicators on one incident")
                    try:
                        cur = c.execute("INSERT INTO iocs(incident_id,type,value,note,added_by,added_at) VALUES(?,?,?,?,?,?)",
                                        (iid, typ, val, str(d.get("note", "")).strip()[:300], un, iso(utcnow())))
                    except sqlite3.IntegrityError:
                        return self.err(409, "That indicator is already recorded on this incident")
                    others = [x[0] for x in c.execute("SELECT DISTINCT incident_id FROM iocs WHERE type=? AND value=? AND incident_id!=?", (typ, val, iid))]
                    event(c, iid, "ioc", f"Indicator added: {typ} {val}", un)
                    audit(c, un, "ioc.add", f"{iid}: {typ} {val}")
                    result = {"ok": True, "id": cur.lastrowid, "type": typ, "value": val, "matches": others}
                elif len(parts) == 5 and parts[4] == "delete" and parts[3].isdigit():
                    x = c.execute("SELECT * FROM iocs WHERE id=? AND incident_id=?", (int(parts[3]), iid)).fetchone()
                    if not x:
                        return self.err(404, "Indicator not found")
                    c.execute("DELETE FROM iocs WHERE id=?", (x["id"],))
                    event(c, iid, "ioc", f"Indicator removed: {x['type']} {x['value']}", un)
                    audit(c, un, "ioc.delete", f"{iid}: {x['type']} {x['value']}")
                else:
                    return self.err(404, "Not found")
            elif op == "checklist":
                if len(parts) == 3:
                    text = str(d.get("text", "")).strip()
                    if not text or len(text) > 200:
                        return self.err(400, "Write a task (up to 200 characters)")
                    nxt = c.execute("SELECT COALESCE(MAX(sort),-1)+1 FROM checklist WHERE incident_id=?", (iid,)).fetchone()[0]
                    cur = c.execute("INSERT INTO checklist(incident_id,text,sort) VALUES(?,?,?)", (iid, text, nxt))
                    audit(c, un, "checklist.add", f"{iid}: {text[:60]}")
                    result = {"ok": True, "id": cur.lastrowid}
                elif len(parts) == 5 and parts[3].isdigit() and parts[4] in ("toggle", "delete"):
                    x = c.execute("SELECT * FROM checklist WHERE id=? AND incident_id=?", (int(parts[3]), iid)).fetchone()
                    if not x:
                        return self.err(404, "Task not found")
                    if parts[4] == "toggle":
                        now_done = 0 if x["done"] else 1
                        c.execute("UPDATE checklist SET done=?, done_by=?, done_at=? WHERE id=?",
                                  (now_done, un if now_done else None, iso(utcnow()) if now_done else None, x["id"]))
                        event(c, iid, "check", ("Completed: " if now_done else "Re-opened: ") + x["text"], un)
                    else:
                        c.execute("DELETE FROM checklist WHERE id=?", (x["id"],))
                        audit(c, un, "checklist.delete", f"{iid}: {x['text'][:60]}")
                else:
                    return self.err(404, "Not found")
            elif op == "playbook":
                n = apply_playbook(c, iid, r["category"])
                if not n:
                    return self.err(409, "This incident already has a checklist")
                audit(c, un, "playbook.apply", f"{iid}: {r['category']}")
                result = {"ok": True, "added": n}
            elif op == "evidence":
                if len(parts) == 3:
                    try:
                        raw = base64.b64decode(str(d.get("data", "")), validate=True)
                        eid, sha = save_evidence(c, iid, un, d.get("filename"), raw, d.get("note"))
                    except (ValueError, TypeError) as e:
                        c.rollback()
                        return self.err(400, "The file could not be read" if "base64" in str(e).lower() or "padding" in str(e).lower() else str(e))
                    result = {"ok": True, "id": eid, "sha256": sha}
                elif len(parts) == 5 and parts[4] == "delete" and parts[3].isdigit():
                    if role != "admin":
                        return self.err(403, "Only administrators can delete evidence")
                    x = c.execute("SELECT * FROM evidence WHERE id=? AND incident_id=?", (int(parts[3]), iid)).fetchone()
                    if not x:
                        return self.err(404, "Evidence not found")
                    c.execute("DELETE FROM evidence WHERE id=?", (x["id"],))
                    try:
                        os.remove(os.path.join(EVIDENCE_DIR, os.path.basename(x["stored_name"])))
                    except OSError:
                        pass
                    event(c, iid, "evidence", f"Evidence removed: {x['filename']}", un)
                    audit(c, un, "evidence.delete", f"{iid}: {x['filename']} sha256={x['sha256']}")
                else:
                    return self.err(404, "Not found")
            elif op == "close":
                note = str(d.get("note", "")).strip()
                n = c.execute("SELECT COUNT(*) FROM events WHERE incident_id=? AND kind IN('note','status')", (iid,)).fetchone()[0]
                if len(note) < 10 or n < 1:
                    return self.err(400, "Add at least one note or status change and a closing summary (10+ characters)")
                t = iso(utcnow())
                c.execute("UPDATE incidents SET status='Closed', closed_at=?, resolved_at=COALESCE(resolved_at,?), resolution=?, root_cause=?, lessons=? WHERE id=?",
                          (t, t, note, str(d.get("root_cause", "")).strip()[:1000], str(d.get("lessons", "")).strip()[:1000], iid))
                event(c, iid, "close", "Incident closed: " + note, un)
                audit(c, un, "incident.close", iid)
            else:
                return self.err(404, "Not found")
        touch(c, iid)
        c.commit()
        self.send(200, result)


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):        # failed TLS handshakes and dropped connections are not bugs
        import sys
        if not isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError)):
            super().handle_error(request, client_address)


def ensure_webhook_token():
    """Auto-provision a local SENTINEL_WEBHOOK_TOKEN if the operator hasn't set one, so the
    attack lab (and any local integration) works out of the box. Saved next to the database,
    never printed in full, never sent anywhere outside this machine."""
    if os.environ.get("SENTINEL_WEBHOOK_TOKEN", "").strip():
        return
    tok_file = os.path.join(DATA_DIR, ".lab_webhook_token")
    tok = ""
    if os.path.exists(tok_file):
        try:
            tok = open(tok_file).read().strip()
        except OSError:
            tok = ""
    if not tok:
        tok = secrets.token_hex(24)
        try:
            with open(tok_file, "w") as f:
                f.write(tok)
        except OSError:
            pass
    os.environ["SENTINEL_WEBHOOK_TOKEN"] = tok


def main():
    ensure_webhook_token()
    init()
    try:
        make_backup("auto")
    except Exception as e:
        print("Backup skipped:", e)
    threading.Thread(target=sla_notification_worker, daemon=True, name="sentinel-sla-notifications").start()
    try:
        srv = QuietServer((HOST, PORT), H)
    except OSError:
        print(f"\n  Port {PORT} is already in use. Close the other copy of the system, or run with a different port:\n"
              f"  set PORT=8080 && python server.py\n")
        raise SystemExit(1)
    if TLS_ON:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        except (OSError, ssl.SSLError) as e:
            print(f"\n  Could not load the TLS certificate or key: {e}\n  Create a test certificate with make-cert, or unset SENTINEL_TLS_CERT / SENTINEL_TLS_KEY.\n")
            raise SystemExit(1)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)   # handshake runs in the request thread
    url = f"{'https' if TLS_ON else 'http'}://{'127.0.0.1' if HOST in ('0.0.0.0', '') else HOST}:{PORT}"
    print(f"\n  SentinelDesk is running at {url}\n  Press Ctrl+C to stop.\n")
    if os.path.isdir(LAB_DIR):
        print("  Tip: on the Dashboard, open \"Live attack feed\" and click \"Start the attack lab\" (admin only)\n"
              "  to see real, locally-generated attacks turn into real incidents here.\n")
    if os.environ.get("NO_BROWSER") != "1":
        threading.Timer(1, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        stop_attack_lab()


if __name__ == "__main__":
    main()
