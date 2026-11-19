"""
Ghost Ledger v4.1 - FIXED
Fixes brutal analysis (2026-11-19) against v4:

P0 FIXED:
1. v4 PDF crash -> set_x before every cell/multi_cell + safe_pdf_text (latin-1, Rs./EUR replace)
2. Raw cmdline storage -> redact_cmdline(), never store --token/--api-key values, store binary only
3. Regex boundaries -> \\b, Anthropic checked BEFORE OpenAI, OpenAI uses (?!ant-) negative lookahead
4. High-by-default processes -> calc_process_risk() starts at 15, dedupe by binary (not PID), no auto Source+Keys
5. Score punishes NOT CONFIGURED -> v2 score: 100 - High*12 - Medium*3, NOT CONFIGURED excluded, Coverage % separate
6. Consent + client + secret opt-in wired -> UI requires consent checkbox, client_name, secret scan OFF by default
7. Clear All Data -> Archive Scan (append-only, no delete of ledger)
8. ORDER BY risk DESC -> CASE WHEN High=0, Medium=1, Low=2
9. Misclassification -> finding_kind checks env BEFORE secret, public before default, NOT CONFIGURED -> Coverage Gap
10. Currency -> Rs. 250 Cr (not $), DPDP Sec 8(5) safeguards / 8(6) breach notice, EU 7% ONLY for Art 5 prohibited
11. ISO 42001 -> A.2 Policy, A.3 Roles, A.4 Resources, A.5 Data (not A.10.2 / A.6.1 / A.5.1 which are ISO 27001)
12. Hash chain -> full SHA-256 (not [:16]), covers findings hash, verify function, no truncation
13. Mask -> no first4/last4 oracle, only len + full sha256 prefix 16 (no secret fragment)
14. Secret scan false assurance -> cap warning, git tracked check, git history check (last 20 commits), UI says PARTIAL not "No secrets"
15. Process matching -> exact binary name + word-boundary regex, cmake != make, continue != Continue app
16. Evidence DONE lines -> checklist reflects ACTUAL state (PRESENT/MISSING/NOT STARTED), no hardcoded DONE
17. MCP discovery -> NEW scan_mcp_configs() for Claude Desktop, Cursor, VS Code, Windsurf + repo-level configs
18. Per-scan snapshots + before/after diff -> scan_assets table preserves every scan, diff by scan_id
19. GitHub public repo -> not auto-High, risk depends on visibility + whether it contains secrets/PII (checked separately)
20. AWS S3 -> checks tags + public ACL/policy, not just lists bucket as Medium

WHAT IS HONEST NOW:
- v4.1 covers well: Endpoint processes (deduplicated), Local repos, Local secrets (partial), MCP configs, Python env, Docker, Ports, GitHub, AWS S3/EC2 (1 region, read-only)
- Partial: Azure/GCP/Okta/Entra/Slack = NOT CONFIGURED placeholders (honest, no fake)
- Not built: SaaS/OAuth discovery (140 tools claim), network traffic classifier, browser extension. Do NOT claim them.
- Score is internal prioritisation, NOT "AUDIT READY" certification. Label is "READY FOR REVIEW (internal)" + coverage.
- This is a discovery + evidence tool, NOT an auditor. Independence: consultant who fixes cannot certify own fixes.

Run: pip install -r requirements.txt ; streamlit run app.py
Env: GITHUB_TOKEN (read-only), AWS_ACCESS_KEY_ID etc. Never paste secrets in chat.
"""
import streamlit as st
import pandas as pd
import hashlib, uuid, os, json, sqlite3, socket, platform, subprocess, glob, re, hmac
from datetime import datetime
from pathlib import Path
from io import BytesIO

try:
    import psutil
except Exception:
    psutil = None
try:
    import requests
except Exception:
    requests = None
try:
    from fpdf import FPDF
except Exception:
    FPDF = None
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

st.set_page_config(page_title="Ghost Ledger v4.1 Fixed | Evidence Scanner", page_icon="👻", layout="wide", initial_sidebar_state="expanded")
st.markdown("""<style>.main-header{font-size:2.5rem;font-weight:700;background:linear-gradient(90deg,#0F7A7E 0%,#002923 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:0.5rem}.sub-header{color:#444;font-size:1.1rem;margin-bottom:1rem}.fix-note{background:#E8F5F5;padding:12px;border-radius:8px;border-left:4px solid #24B0B9}</style>""", unsafe_allow_html=True)

DB_PATH = Path(__file__).parent / "ghost_ledger.db"

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()]
        if cols and len(cols) != 19:
            conn.execute("DROP TABLE IF EXISTS assets")
    except Exception:
        pass
    conn.execute("""CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY, name TEXT, category TEXT, type TEXT, source TEXT,
        risk TEXT, status TEXT, owner TEXT, model TEXT, data_access TEXT,
        evidence TEXT, first_seen TEXT, last_seen TEXT, actions_count INTEGER, policy_violations INTEGER,
        cloud TEXT, region TEXT, repo_url TEXT, scan_id TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ledger (
        id TEXT PRIMARY KEY, timestamp TEXT, action TEXT, agent_id TEXT, details TEXT, severity TEXT, hash TEXT, prev_hash TEXT, findings_hash TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, timestamp TEXT, scope TEXT, total INTEGER, high INTEGER, mode TEXT, live_count INTEGER, simulated_count INTEGER,
        client_name TEXT, consent INTEGER, secret_scan_enabled INTEGER, coverage_pct REAL, findings_hash TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS scan_assets (
        id TEXT PRIMARY KEY, scan_id TEXT, asset_name TEXT, risk TEXT, status TEXT, snapshot_json TEXT, created_at TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS archive_assets (
        id TEXT PRIMARY KEY, archived_at TEXT, scan_id TEXT, asset_json TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS allowlist (
        pattern TEXT PRIMARY KEY, reason TEXT, created_at TEXT
    )""")
    # migrate old ledger/scans if missing columns
    try:
        lcols = [r[1] for r in conn.execute("PRAGMA table_info(ledger)").fetchall()]
        if "findings_hash" not in lcols:
            conn.execute("ALTER TABLE ledger ADD COLUMN findings_hash TEXT")
    except Exception:
        pass
    try:
        scols = [r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
        for col, typ in [("client_name","TEXT"),("consent","INTEGER"),("secret_scan_enabled","INTEGER"),("coverage_pct","REAL"),("findings_hash","TEXT")]:
            if col not in scols:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {typ}")
    except Exception:
        pass
    conn.commit(); conn.close()

init_db()

# ---------- SAFE HELPERS ----------
def safe_pdf_text(s):
    """FPDF Helvetica is latin-1 only. Replace unicode that would crash, keep meaning."""
    if s is None:
        return ""
    s = str(s)
    replacements = {"₹":"Rs. ", "€":"EUR ", "—":"-", "–":"-", "’":"'", "‘":"'", "“":'"', "”":'"', "•":"-", "✓":"[OK]", "✗":"[X]", "👻":"[Ghost]"}
    for k,v in replacements.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "ignore").decode("latin-1")

def mask_secret(s):
    """FIX: No first4/last4 oracle. Only length + sha256 prefix, no secret fragment."""
    if not s:
        return "***masked***"
    h = hashlib.sha256(s.encode(errors="ignore")).hexdigest()
    return f"***masked*** (len={len(s)}, sha256:{h[:16]}...)"

def redact_cmdline(cmdline_list):
    """FIX: Never store raw cmdline. Redact --token/--api-key/--password values, keep binary only."""
    if not cmdline_list:
        return "binary only, args redacted"
    # First element is binary
    binary = str(cmdline_list[0])[:120]
    redacted_args = []
    skip_next = False
    secret_flags = {"--token","--api-key","--apikey","--api_key","--password","--secret","--auth","--authorization","-t","--key"}
    for tok in cmdline_list[1:]:
        if skip_next:
            redacted_args.append("[REDACTED]")
            skip_next = False
            continue
        low = str(tok).lower()
        if any(f in low for f in ["token=","api-key=","api_key=","apikey=","password=","secret=","authorization=","bearer"]):
            # keep key name, redact value after =
            if "=" in str(tok):
                redacted_args.append(str(tok).split("=",1)[0] + "=[REDACTED]")
            else:
                redacted_args.append("[REDACTED]")
        elif low in secret_flags:
            redacted_args.append(str(tok))
            skip_next = True
        elif len(str(tok)) > 40 and re.search(r"[A-Za-z0-9_\-]{32,}", str(tok)):
            redacted_args.append("[POSSIBLE_SECRET_REDACTED]")
        else:
            redacted_args.append(str(tok)[:40])
    # Never return full args if they look like secrets - cap at 120 chars, no long tokens
    joined = " ".join(redacted_args)[:120]
    return f"binary: {binary} | args: {joined} | args_redacted: True"

def compute_findings_hash(assets):
    payload = json.dumps(sorted([(a.get("name",""), a.get("risk",""), a.get("status","")) for a in assets]), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()

def add_ledger_entry(action, agent_id=None, details="", severity="Info", findings_hash=""):
    conn = get_db()
    row = conn.execute("SELECT hash FROM ledger ORDER BY rowid DESC LIMIT 1").fetchone()
    prev = row[0] if row else "genesis"
    ts = datetime.now().isoformat()
    # FIX: Full SHA-256, not [:16], covers prev + ts + action + details + findings_hash
    h = hashlib.sha256(f"{prev}|{ts}|{action}|{details}|{findings_hash}".encode()).hexdigest()
    eid = f"led-{uuid.uuid4().hex[:10]}"
    try:
        conn.execute("INSERT INTO ledger (id,timestamp,action,agent_id,details,severity,hash,prev_hash,findings_hash) VALUES (?,?,?,?,?,?,?,?,?)", (eid, ts, action, agent_id, details, severity, h, prev, findings_hash))
    except Exception:
        conn.execute("INSERT INTO ledger (id,timestamp,action,agent_id,details,severity,hash,prev_hash) VALUES (?,?,?,?,?,?,?,?)", (eid, ts, action, agent_id, details, severity, h, prev))
    conn.commit(); conn.close()
    return h

def verify_ledger_chain():
    conn = get_db()
    rows = conn.execute("SELECT * FROM ledger ORDER BY rowid ASC").fetchall()
    conn.close()
    prev = "genesis"
    for r in rows:
        d = dict(r)
        expected = hashlib.sha256(f"{prev}|{d['timestamp']}|{d['action']}|{d['details']}|{d.get('findings_hash') or ''}".encode()).hexdigest()
        if expected != d["hash"]:
            return False, f"Break at {d['id']} {d['timestamp']}"
        prev = d["hash"]
    return True, f"OK - {len(rows)} entries verified, full SHA-256 chain intact"

def load_assets():
    conn = get_db()
    # FIX: ORDER BY CASE, not alphabetical DESC (which gave Medium, Low, High)
    rows = conn.execute("SELECT * FROM assets ORDER BY CASE risk WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END, last_seen DESC").fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try: d["data_access"] = json.loads(d["data_access"] or "[]")
        except: d["data_access"] = []
        out.append(d)
    return out

def load_ledger():
    conn = get_db()
    rows = conn.execute("SELECT * FROM ledger ORDER BY rowid DESC LIMIT 100").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def load_scans():
    conn = get_db()
    rows = conn.execute("SELECT * FROM scans ORDER BY rowid DESC LIMIT 20").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def load_allowlist():
    conn = get_db()
    rows = conn.execute("SELECT * FROM allowlist").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def is_allowlisted(name):
    for a in load_allowlist():
        if a["pattern"].lower() in name.lower():
            return True
    return False

# ---------- CORRECTED COMPLIANCE MAPS ----------
# ISO 42001 Annex A: A.2 Policy, A.3 Roles, A.4 Resources, A.5 Data. NOT A.10.2/A.6.1/A.5.1 (those are ISO 27001).
# DPDP: Sec 8(5) safeguards, Sec 8(6) breach notification to Board + affected persons. NOT 8(4)/8(7).
# EU AI Act: Art 15 applies ONLY to high-risk systems. Art 9 risk mgmt ONLY high-risk. 7% ONLY Art 5 prohibited practices.
# GDPR: Art 32 security, Art 33 breach notification (72h), Art 5 accountability.
FRAMEWORK_MAP = {
    "Secret in code": {"EU AI Act": "Art 15 (ONLY if high-risk system) + Art 9 (ONLY if high-risk)", "ISO 42001": "A.4 Resources + A.5 Data for AI", "NIST AI RMF": "MAP 2 + MANAGE 1", "SOC 2": "CC6.1 + CC7.2", "DPDP / GDPR": "DPDP Sec 8(5) Safeguards / GDPR Art 32 Security. NOT a breach by itself - breach needs personal data exposure (DPDP Sec 8(6) / GDPR Art 33)"},
    "Secret in env": {"EU AI Act": "Art 15 (ONLY if high-risk)", "ISO 42001": "A.4 Resources + A.5 Data", "NIST AI RMF": "GOVERN 1 + MANAGE 1", "SOC 2": "CC6.1", "DPDP / GDPR": "DPDP Sec 8(5) / GDPR Art 32"},
    "Public repo / bucket": {"EU AI Act": "Art 15 (ONLY if high-risk) + Art 10 Data (ONLY if high-risk)", "ISO 42001": "A.5 Data + A.4 Resources", "NIST AI RMF": "MAP 2 + MEASURE 2", "SOC 2": "CC6.1 + CC6.6", "DPDP / GDPR": "DPDP Sec 8(5) + Sec 8(6) breach notice IF personal data exposed / GDPR Art 32 + Art 33"},
    "No owner / Ghost AI": {"EU AI Act": "Art 9 Risk Mgmt (ONLY if high-risk) + Art 26 Deployer duties (ONLY if high-risk). 7% fine does NOT apply here - see below.", "ISO 42001": "A.3 Roles + A.2 AI Policy", "NIST AI RMF": "GOVERN 1 + MAP 1", "SOC 2": "CC1.1 + CC6.1", "DPDP / GDPR": "DPDP Sec 8(1)-(2) obligations / GDPR Art 5 Accountability"},
    "No MFA / Orphan account": {"EU AI Act": "Art 15 (ONLY if high-risk)", "ISO 42001": "A.4 Resources", "NIST AI RMF": "GOVERN 1", "SOC 2": "CC6.1 + CC6.2", "DPDP / GDPR": "DPDP Sec 8(5) / GDPR Art 32"},
    "MCP server - no auth / secret in config": {"EU AI Act": "Art 15 (ONLY if high-risk) + Art 9 (ONLY if high-risk)", "ISO 42001": "A.4 Resources + A.5 Data", "NIST AI RMF": "MAP 2 + MANAGE 1", "SOC 2": "CC6.1 + CC6.6", "DPDP / GDPR": "DPDP Sec 8(5) / GDPR Art 32"},
    "Coverage gap - Not Configured": {"EU AI Act": "Cannot assess - no evidence", "ISO 42001": "Cannot assess - no evidence", "NIST AI RMF": "Cannot assess", "SOC 2": "Cannot assess", "DPDP / GDPR": "Cannot assess - coverage gap, not a finding"},
    "Default": {"EU AI Act": "Art 9 (ONLY if high-risk)", "ISO 42001": "A.3 Roles + A.4 Resources", "NIST AI RMF": "GOVERN + MAP", "SOC 2": "CC6.1", "DPDP / GDPR": "DPDP Sec 8(5) / GDPR Art 32"},
}

REMEDIATION_LIB = {
    "Secret in code": {"fix": "1. Revoke the key now (do NOT just delete file). 2. Check git history: git log -p -- .env - if tracked, purge via git filter-repo / BFG. 3. Check if .env is tracked: git ls-files -- .env - if tracked, untrack + add .gitignore. 4. Turn on GitHub push protection. 5. Re-scan to prove revoked.", "owner": "Engineering Lead", "days": 1, "cost_if_ignored": "IF secret gives access to personal data: DPDP Sec 8(5) failure up to Rs. 250 Cr per violation type + Sec 8(6) breach notice. GDPR Art 32/33. Secret alone without personal data exposure is NOT automatically a DPDP breach - verify exposure first."},
    "Secret in env": {"fix": "1. Move key to vault (AWS Secrets Manager / HashiCorp Vault). 2. Rotate key. 3. Never keep keys in .env on laptop. 4. Re-scan.", "owner": "Security Lead", "days": 1, "cost_if_ignored": "Laptop stolen / repo leaked = all keys stolen. Verify if keys were ever committed."},
    "Public repo / bucket": {"fix": "1. Make repo / bucket private now (check ACL + policy, not just listing). 2. Check access logs for who accessed it. 3. If personal data was exposed, assess DPDP Sec 8(6) / GDPR Art 33 breach notice. 4. Add access review. 5. Re-scan.", "owner": "Cloud Lead", "days": 1, "cost_if_ignored": "Public exposure of personal data may trigger breach notification (DPDP Sec 8(6) / GDPR Art 33 in 72h). Public repo without personal data is still a risk, not automatically a breach."},
    "No owner / Ghost AI": {"fix": "1. Name an owner (A.3). 2. Write 1-page AI use + risk (A.2 policy). 3. Add to AI Register. 4. Get approval.", "owner": "AI Owner + CISO", "days": 7, "cost_if_ignored": "No accountability. EU AI Act: NO 7% fine here. 7% is ONLY for Art 5 prohibited practices. Missing owner/register for high-risk systems falls under Art 99(4): up to EUR 15M or 3% turnover. Do NOT quote 7% for this."},
    "No MFA / Orphan account": {"fix": "1. Turn on MFA. 2. Remove orphan account. 3. Review access every 90 days.", "owner": "IT / Identity Lead", "days": 3, "cost_if_ignored": "Account takeover, full system breach. DPDP Sec 8(5) safeguards."},
    "MCP server - no auth / secret in config": {"fix": "1. Check MCP config: if server has no auth, add OAuth / API key auth or restrict to localhost. 2. Remove secrets from config - use env vault. 3. Pin server version, verify publisher. 4. Log tool calls. 5. Re-scan.", "owner": "AI Platform Lead", "days": 2, "cost_if_ignored": "MCP server without auth can be abused for RCE / data exfiltration. 30-82% of public MCP servers have exploitable flaws (2026 scans)."},
    "Coverage gap - Not Configured": {"fix": "Configure connector (read-only) to get evidence. Until then, this is UNKNOWN, not Low risk.", "owner": "Assigned Owner", "days": 7, "cost_if_ignored": "Unknown = cannot prove compliance. Do not claim audit-ready with coverage gaps."},
    "Default": {"fix": "1. Name owner. 2. Fix now. 3. Add control. 4. Re-scan to prove fixed.", "owner": "Assigned Owner", "days": 7, "cost_if_ignored": "Audit cannot be proven, deal / funding may be blocked. This tool does NOT certify audit-ready."},
}

def finding_kind(asset_name, asset=None):
    # FIX: Order matters. Env BEFORE generic secret, NOT CONFIGURED before Ghost, MCP before default.
    n = (asset_name or "").lower()
    if "not configured" in n or "not connected" in n:
        return "Coverage gap - Not Configured"
    if "mcp" in n:
        return "MCP server - no auth / secret in config"
    if "env secrets" in n or "env keys" in n:
        return "Secret in env"
    if "secrets found" in n or "secret" in n:
        return "Secret in code"
    if "public" in n:
        return "Public repo / bucket"
    if "s3" in n and "public" in n:
        return "Public repo / bucket"
    if "ghost" in n or "no owner" in n:
        return "No owner / Ghost AI"
    if "mfa" in n or "orphan" in n:
        return "No MFA / Orphan account"
    return "Default"

def build_simple_findings(assets):
    rows = []
    for a in assets:
        # FIX: Exclude allowlisted + NOT CONFIGURED from findings (they are coverage gaps, not findings)
        if a.get("status") == "Allowlisted":
            continue
        if "NOT CONFIGURED" in str(a.get("source","")) or "Not Configured" in str(a.get("status","")):
            continue
        if a.get("risk") in ("High","Medium") or "Secrets" in a.get("name","") or "Env Secrets" in a.get("name",""):
            kind = finding_kind(a.get("name",""), a)
            fm = FRAMEWORK_MAP.get(kind, FRAMEWORK_MAP["Default"])
            rem = REMEDIATION_LIB.get(kind, REMEDIATION_LIB["Default"])
            rows.append({"asset": a.get("name",""), "risk": a.get("risk",""), "kind": kind, "framework": fm, "fix": rem["fix"], "owner": rem["owner"], "days": rem["days"], "cost": rem["cost_if_ignored"], "path": a.get("evidence","")[:120]})
    return rows

def simple_readiness_score(assets):
    # FIX v2: Do NOT penalise NOT CONFIGURED. Score = prioritisation only, NOT certification.
    # High*12 + Medium*3, allowlisted excluded, NOT CONFIGURED excluded from penalty but reported as coverage.
    active = [a for a in assets if a.get("status") != "Allowlisted" and "NOT CONFIGURED" not in str(a.get("source",""))]
    high = sum(1 for a in active if a.get("risk")=="High")
    med = sum(1 for a in active if a.get("risk")=="Medium")
    score = max(0, 100 - high*12 - med*3)
    total = len(assets) if assets else 1
    not_config = sum(1 for a in assets if "NOT CONFIGURED" in str(a.get("source","")))
    coverage = round(100 * (total - not_config) / total, 1) if total else 0.0
    # Label is INTERNAL, not AUDIT READY certification
    if score >= 80 and coverage >= 80:
        level = "READY FOR REVIEW (internal) - Highs fixed, coverage >=80%"
    elif score >= 60:
        level = "ALMOST READY (internal) - Fix Highs in 7 days"
    elif score >= 40:
        level = "NOT READY (internal) - Fix Highs + assign owners"
    else:
        level = "HIGH RISK (internal) - Stop and fix now"
    return score, level, coverage

def calc_risk(data_access, has_keys=False, is_external=False, is_personal=False, is_prod=False):
    # Kept for compat, but NOT used for processes anymore (see calc_process_risk)
    score = 0
    sensitive = {"Source Code","API Keys","Customer Data","Finance Systems","Bank Details","Confidential Strategy Docs","HR Docs","Customer Emails","Production DB","PII","Secrets"}
    for d in data_access:
        if d in sensitive: score += 25
        elif "Internal" in d or "CRM" in d: score += 12
        else: score += 5
    if has_keys: score += 30
    if is_external: score += 20
    if is_personal: score += 20
    if is_prod: score += 25
    if score >= 70: return "High"
    if score >= 35: return "Medium"
    return "Low"

def calc_process_risk(binary_name, is_personal=False, has_token_in_cmd=False, is_prod=False, is_external=False):
    # FIX: Start at 15 (AI tool present), not 80. Need evidence to reach High.
    # Personal + token = 75 = High (personal use + secret in cmd is real exfil risk)
    score = 15
    if is_personal: score += 30
    if has_token_in_cmd: score += 30
    if is_prod: score += 25
    if is_external: score += 10
    # Helper processes (Cursor Helper, Electron Helper) are NOT separate Highs - they are same app
    if "helper" in binary_name.lower():
        score -= 10
    if score >= 70: return "High"
    if score >= 35: return "Medium"
    return "Low"

# FIXED SECRET PATTERNS: word boundaries, Anthropic BEFORE OpenAI, OpenAI excludes sk-ant-
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b")),
    ("GitHub Fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    # Anthropic FIRST, else OpenAI double-fires
    ("Anthropic Key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI Key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}\b")),
    ("Generic Secret Assign", re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*=\s*['\"][^'\"]{8,}['\"]")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

# ---------- LOCAL SCANNERS ----------
def scan_system_info(scan_id):
    try:
        host = socket.gethostname()
        return [{"name": f"{host} - Host ({platform.system()} {platform.release()})","category":"Infrastructure","type":"Endpoint / Server","source":"Local OS","risk":"Low","status":"Active","owner":os.environ.get("USER","unknown"),"model":f"{platform.machine()} / Python {platform.python_version()}","data_access":["OS Info"],"evidence":f"Hostname={host}, OS={platform.platform()}, Arch={platform.machine()}","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id}]
    except Exception:
        return []

def scan_processes(scan_id):
    assets = []
    if not psutil:
        return assets
    # FIX: Dedupe by binary, not PID. Cursor spawns 10+ helpers = 1 asset, not 10 Highs.
    grouped = {}
    for p in psutil.process_iter(['pid','name','exe','cmdline','username']):
        try:
            info = p.info
            raw_name = (info.get('name') or "")
            name_low = raw_name.lower()
            APPLE_SYSTEM_NAMES = {"cursoruiviewservice","coreservicesuiagent","trustd","launchd","kernel_task","windowserver","loginwindow","mds","mdworker","bird","cloudd","distnoted","cfprefsd"}
            if name_low in APPLE_SYSTEM_NAMES:
                continue
            exe = (info.get('exe') or "")
            if exe.startswith("/System/") or exe.startswith("/usr/libexec/") or "/System/Library/" in exe:
                continue
            cmd_list = info.get('cmdline') or []
            cmd_joined = " ".join(cmd_list).lower()
            # FIX: Exact binary match + word-boundary, not substring. cmake != make, continue != Continue
            # Patterns as (binary_exact, regex_on_cmd)
            AI_BINARIES = {"cursor","code","windsurf","ollama","aider","claude","chatgpt","copilot","gemini","perplexity","crewai","autogen","langchain","n8n","zapier","tabnine","codeium","amazon q"}
            # Use regex \b for cmdline
            is_ai = False
            matched = ""
            # 1) binary name exact / startswith
            base = name_low.replace(".exe","").replace(".app","")
            if base in AI_BINARIES or any(base.startswith(b+" ") or base==b for b in AI_BINARIES):
                is_ai = True
                matched = base
            else:
                # 2) cmdline word-boundary check for known AI CLIs, NOT generic words like make/continue
                for pat in [r"\bcursor\b", r"\bollama\b", r"\bclaude\b", r"\bcopilot\b", r"\bwindsurf\b", r"\baider\b", r"\bcodeium\b", r"\bcrewai\b", r"\blangchain\b", r"\bn8n\b"]:
                    if re.search(pat, cmd_joined):
                        # Extra guard: cursor must be Cursor.app
                        if "cursor" in pat and "cursor.app" not in exe.lower() and "applications/cursor" not in cmd_joined and base != "cursor":
                            continue
                        is_ai = True
                        matched = pat
                        break
            if not is_ai:
                continue
            # Group key = binary + exe path, not PID
            key = (raw_name, exe)
            if key not in grouped:
                grouped[key] = {"name": raw_name, "exe": exe, "username": info.get('username') or "unknown", "pids": [], "cmd_sample": cmd_list, "is_personal": "personal" in cmd_joined}
            grouped[key]["pids"].append(info.get('pid'))
            # keep first cmd sample
        except Exception:
            continue
    for (raw_name, exe), g in grouped.items():
        is_personal = g["is_personal"]
        # Check token in cmd WITHOUT storing it
        has_token = any(t in " ".join(g["cmd_sample"]).lower() for t in ["--token","--api-key","api_key=","token="])
        risk = calc_process_risk(raw_name, is_personal=is_personal, has_token_in_cmd=has_token)
        if is_allowlisted(raw_name):
            risk = "Low"
        # FIX: Evidence is redacted, no raw cmdline
        evidence = redact_cmdline(g["cmd_sample"]) + f" | instances: {len(g['pids'])} PIDs grouped as 1 asset (PIDs: {','.join(map(str, g['pids'][:5]))})"
        assets.append({"name": f"{raw_name} - LIVE ({len(g['pids'])} instances grouped)","category":"Agent / Software","type":"Running Process","source":"Endpoint Process - LIVE","risk":risk,"status":"Allowlisted" if is_allowlisted(raw_name) else "Active","owner":g["username"],"model":exe or raw_name.lower(),"data_access":["Process Memory"] if not is_personal else ["Process Memory","Personal Use"],"evidence":evidence,"first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":len(g["pids"]),"policy_violations":1 if is_personal else 0,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id})
    return assets

def scan_python_env(scan_id):
    assets = []
    try:
        import pkg_resources
        installed = {d.key for d in pkg_resources.working_set}
        AI_PY = ["openai","anthropic","langchain","langgraph","crewai","autogen","llama-index","transformers","ollama","google-generativeai","cohere","mistralai","groq","together","replicate","chromadb","pinecone-client","weaviate-client","qdrant-client"]
        found = [p for p in AI_PY if p.lower().replace("-","_") in {x.replace("-","_") for x in installed}]
        if found:
            # FIX: Python libs alone are NOT High. Medium if libs present, High only if keys in env too (checked separately)
            assets.append({"name": f"Python AI Stack - {', '.join(found[:6])} - LIVE","category":"Software","type":"Python Packages","source":"Local Python Env - LIVE","risk":"Medium","status":"Active","owner":os.environ.get("USER","unknown"),"model":"pip packages","data_access":["Source Code"],"evidence":f"Found AI libs: {', '.join(found)} | Libs alone do NOT mean secrets exposed - check secret scan.","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":len(found),"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id})
    except Exception:
        pass
    return assets

def scan_docker(scan_id):
    assets = []
    try:
        out = subprocess.check_output(["docker","ps","--format","{{.Names}}|{{.Image}}|{{.Status}}"], text=True, timeout=6)
        for line in out.strip().splitlines():
            if not line.strip(): continue
            parts = line.split("|")
            name = parts[0] if parts else line[:60]
            img = parts[1] if len(parts) > 1 else ""
            assets.append({"name": f"Docker: {name} ({img}) - LIVE","category":"Infrastructure","type":"Docker Container","source":"Docker - LIVE","risk":"Medium" if "ai" in img.lower() or "ollama" in img.lower() else "Low","status":"Active","owner":os.environ.get("USER","unknown"),"model":img,"data_access":["Container FS"],"evidence":f"Container {name} image {img}","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id})
    except Exception:
        pass
    return assets

def scan_ports(scan_id):
    assets = []
    try:
        if psutil:
            conns = psutil.net_connections(kind='inet')
            ports = sorted(set(c.laddr.port for c in conns if c.status == 'LISTEN'))
            if ports:
                assets.append({"name": f"Listening Ports - {len(ports)} ports - LIVE","category":"Network","type":"Open Ports","source":"Local Network - LIVE","risk":"Medium" if any(p in [8501,3000,8000,5000,5432,6379] for p in ports) else "Low","status":"Active","owner":os.environ.get("USER","unknown"),"model":"netstat via psutil","data_access":["Network"],"evidence":f"Ports: {', '.join(map(str, ports[:20]))}","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":len(ports),"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id})
    except Exception:
        pass
    return assets

# ---------- MCP DISCOVERY (NEW, Step 3) ----------
def scan_mcp_configs(scan_id):
    """Read MCP config files for Claude Desktop, Cursor, VS Code, Windsurf + repo-level configs.
    Lists each server with auth status + secrets in config (masked, never stored). ~1 day work, now built."""
    assets = []
    home = Path.home()
    candidates = []
    # Global configs
    candidates += [
        home / "Library/Application Support/Claude/claude_desktop_config.json",
        home / ".cursor/mcp.json",
        home / "Library/Application Support/Cursor/User/mcp.json",
        home / "Library/Application Support/Cursor/User/settings.json",
        home / ".vscode/mcp.json",
        home / "Library/Application Support/Code/User/mcp.json",
        home / "Library/Application Support/Code/User/settings.json",
        home / ".config/Code/User/mcp.json",
        home / "Library/Application Support/Windsurf/User/mcp.json",
        home / ".windsurf/mcp.json",
        home / ".codeium/windsurf/mcp_config.json",
        home / ".config/claude/mcp.json",
        home / ".cursor/mcp.json",
    ]
    # Repo-level configs (find_local_repos)
    try:
        for rp in find_local_repos()[:20]:
            for rel in [".cursor/mcp.json", ".vscode/mcp.json", ".mcp.json", "mcp.json"]:
                candidates.append(Path(rp) / rel)
    except Exception:
        pass
    seen_servers = set()
    for cfg_path in candidates:
        try:
            if not cfg_path.exists():
                continue
            txt = cfg_path.read_text(errors="ignore")
            try:
                data = json.loads(txt)
            except Exception:
                continue
            servers = {}
            if isinstance(data, dict):
                if "mcpServers" in data and isinstance(data["mcpServers"], dict):
                    servers = data["mcpServers"]
                elif "mcp" in data and isinstance(data["mcp"], dict) and "servers" in data["mcp"]:
                    servers = data["mcp"]["servers"]
                elif "servers" in data and isinstance(data["servers"], dict):
                    servers = data["servers"]
            if not servers:
                continue
            for srv_name, srv in servers.items():
                if not isinstance(srv, dict):
                    continue
                key = (str(cfg_path), srv_name)
                if key in seen_servers:
                    continue
                seen_servers.add(key)
                command = str(srv.get("command","") or srv.get("cmd","") or "")
                args = srv.get("args", []) or []
                url = str(srv.get("url","") or srv.get("endpoint","") or "")
                env = srv.get("env", {}) or {}
                headers = srv.get("headers", {}) or {}
                # Auth analysis
                has_secret_in_env = any(any(k in kk.upper() for k in ["API_KEY","TOKEN","SECRET","PASSWORD","KEY"]) for kk in list(env.keys()) + list(headers.keys()))
                # Check if env values look like real secrets (masked, never stored)
                secret_keys = [k for k in env.keys() if any(x in k.upper() for x in ["API_KEY","TOKEN","SECRET","PASSWORD"])]
                auth_status = "No Auth Detected"
                if has_secret_in_env:
                    auth_status = f"Auth via env: {', '.join(secret_keys[:3])} (values masked, not stored)"
                elif "oauth" in str(srv).lower() or "authorization" in str(headers).lower():
                    auth_status = "OAuth / Authorization header"
                elif url.startswith("http"):
                    auth_status = "Remote HTTP - check auth (no env key found)"
                elif command:
                    auth_status = "Local stdio - runs as local user, check file perms"
                # Risk: no auth + remote = High, secret in config = High (should be vault), local stdio + no secret = Low/Medium
                if url.startswith("http") and not has_secret_in_env:
                    risk = "High"
                elif has_secret_in_env:
                    risk = "High"
                elif command and "npx" in command:
                    risk = "Medium"
                else:
                    risk = "Low"
                if is_allowlisted(srv_name):
                    risk = "Low"
                evidence = f"Config: {cfg_path} | Server: {srv_name} | Command: {command[:80]} | Args: {str(args)[:80]} | URL: {url[:80]} | Auth: {auth_status} | Env keys (names only): {', '.join(secret_keys) if secret_keys else 'none'}"
                assets.append({"name": f"MCP Server: {srv_name} - {auth_status.split(':')[0]} - LIVE","category":"Agent / Software","type":"MCP Server","source":"MCP Config - LIVE","risk":risk,"status":"Allowlisted" if is_allowlisted(srv_name) else "Active","owner":os.environ.get("USER","unknown"),"model":command or url or "mcp","data_access":["MCP Tools","Config Secrets"] if has_secret_in_env else ["MCP Tools"],"evidence":evidence,"first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":1 if risk=="High" else 0,"cloud":"On-Prem / Local","region":"local","repo_url":str(cfg_path),"scan_id":scan_id})
        except Exception as e:
            pass
    if not assets:
        assets.append({"name": "MCP - No MCP configs found - LIVE","category":"Agent / Software","type":"MCP Server","source":"MCP Config - LIVE","risk":"Low","status":"Active","owner":os.environ.get("USER","unknown"),"model":"mcp discovery","data_access":[],"evidence":"Checked Claude Desktop, Cursor, VS Code, Windsurf global + repo-level .cursor/mcp.json, .vscode/mcp.json, .mcp.json. No configs found.","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":0,"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id})
    return assets

def find_local_repos():
    roots = []
    home = Path.home()
    for cand in [home / "Downloads", home / "Documents", home / "Projects", home / "Desktop", home / "Code", home / "work", home]:
        if cand.exists():
            roots.append(cand)
    repos = []
    seen = set()
    for root in roots:
        try:
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                depth = Path(dirpath).relative_to(root).parts
                if len(depth) > 4:
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if d not in {".git","node_modules","venv",".venv","__pycache__",".next","Library",".cache"} and not d.startswith(".")]
                if ".git" in os.listdir(dirpath):
                    rp = str(Path(dirpath))
                    if rp not in seen:
                        seen.add(rp)
                        repos.append(rp)
                    dirnames[:] = []
                if len(repos) >= 60:
                    return repos
        except Exception:
            continue
    return repos

def scan_local_repos(scan_id):
    assets = []
    for rp in find_local_repos():
        name = Path(rp).name
        assets.append({"name": f"Local Repo: {name} - LIVE","category":"Repository","type":"Git Repo (Local)","source":"Filesystem - LIVE","risk":"Medium","status":"Active","owner":os.environ.get("USER","unknown"),"model":"git","data_access":["Source Code"],"evidence":f"Path: {rp}","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":rp,"scan_id":scan_id})
    return assets

def is_file_tracked(repo_path, file_path):
    try:
        out = subprocess.check_output(["git","-C",str(repo_path),"ls-files","--",str(file_path)], text=True, timeout=5)
        return bool(out.strip())
    except Exception:
        return False

def scan_git_history_for_secrets(repo_path, max_commits=20):
    """Check git history (where leaks actually live) for secrets in last N commits. Returns count + sample (masked)."""
    try:
        out = subprocess.check_output(["git","-C",str(repo_path),"log","--all","-p",f"-{max_commits}","--","*.env","*.py","*.js","*.json"], text=True, timeout=10, errors="ignore")
        count = 0
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(out):
                count += 1
                if count >= 5:
                    break
        return count
    except Exception:
        return 0

def scan_secrets(scan_id, enabled=False):
    # FIX: Secret scan is OPT-IN, default OFF. If not enabled, return coverage gap, not false "No secrets".
    if not enabled:
        return [{"name": "Secret Scan - Not Enabled (opt-in OFF) - COVERAGE GAP","category":"Security","type":"Secret Scan","source":"Secret Scanner - NOT CONFIGURED","risk":"Low","status":"Not Configured","owner":os.environ.get("USER","unknown"),"model":"opt-in","data_access":[],"evidence":"Secret scan was OFF (default). Tick 'Enable secret scan' in sidebar to run it. No claim of 'No secrets found' can be made.","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":0,"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id}]
    assets = []
    repos = find_local_repos()
    for rp in repos:
        findings = []
        files_scanned = 0
        capped = False
        git_history_hits = 0
        env_tracked = None
        try:
            # Check .env tracked status
            env_path = Path(rp) / ".env"
            if env_path.exists():
                env_tracked = is_file_tracked(rp, ".env")
            git_history_hits = scan_git_history_for_secrets(rp, max_commits=20)
            count_files = 0
            for dirpath, dirnames, filenames in os.walk(rp):
                dirnames[:] = [d for d in dirnames if d not in {".git","node_modules","venv",".venv","__pycache__"}]
                for fn in filenames:
                    if count_files > 200:
                        capped = True
                        break
                    if not fn.endswith((".py",".js",".ts",".env",".json",".yaml",".yml",".toml",".txt",".md")): continue
                    fp = Path(dirpath) / fn
                    if fp.stat().st_size > 200000: continue
                    count_files += 1
                    files_scanned += 1
                    try:
                        txt = fp.read_text(errors="ignore")
                    except Exception:
                        continue
                    for label, pat in SECRET_PATTERNS:
                        for m in pat.finditer(txt):
                            sec = m.group(0)
                            findings.append(f"{label} in {fn}: {mask_secret(sec)}")
                            if len(findings) >= 10: break
                    if len(findings) >= 10: break
        except Exception:
            continue
        # FIX: Evidence includes cap warning, git history, tracked status
        extra = []
        if capped:
            extra.append("PARTIAL SCAN: capped at 200 files/repo, 10 findings - NOT exhaustive")
        if git_history_hits:
            extra.append(f"GIT HISTORY: {git_history_hits} secret-like matches in last 20 commits (masked) - check git log -p")
        if env_tracked is True:
            extra.append(".env IS TRACKED in git (git ls-files) - HIGH: purge history with filter-repo/BFG")
        elif env_tracked is False:
            extra.append(".env NOT tracked (git ls-files empty) - good, but still rotate if ever committed")
        if findings or git_history_hits:
            ev = "; ".join(findings[:5])
            if extra:
                ev += " | " + " | ".join(extra)
            assets.append({"name": f"Secrets Found: {Path(rp).name} - {len(findings)} findings - LIVE","category":"Security","type":"Secret Scan","source":"Secret Scanner - LIVE","risk":"High","status":"Active","owner":os.environ.get("USER","unknown"),"model":"regex secret scan","data_access":["Secrets","Source Code"],"evidence":ev,"first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":len(findings),"policy_violations":len(findings),"cloud":"On-Prem / Local","region":"local","repo_url":rp,"scan_id":scan_id})
        else:
            # FIX: Never say "No secrets found" as absolute. Say PARTIAL / NO MATCHES IN SCOPED FILES
            ev = f"Scanned {files_scanned} files (capped 200) + git history last 20 commits - no regex matches in scoped files. " + ("PARTIAL: cap hit. " if capped else "") + "This is NOT proof of no secrets - git history, untracked files, and files >200KB not fully covered."
            if extra:
                ev += " | " + " | ".join(extra)
            assets.append({"name": f"Secret Scan - No matches in scoped files: {Path(rp).name} - PARTIAL","category":"Security","type":"Secret Scan","source":"Secret Scanner - LIVE","risk":"Low","status":"Active","owner":os.environ.get("USER","unknown"),"model":"regex secret scan","data_access":[],"evidence":ev,"first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":0,"policy_violations":0,"cloud":"On-Prem / Local","region":"local","repo_url":rp,"scan_id":scan_id})
    return assets

def scan_env_keys(scan_id):
    assets = []
    keys = [k for k in os.environ.keys() if any(x in k.upper() for x in ["API_KEY","TOKEN","SECRET","PASSWORD","PRIVATE"])]
    if keys:
        # FIX: Only names, never values, and note that env presence alone is not a breach
        masked = [f"{k}=***masked***" for k in keys[:10]]
        assets.append({"name": f"Env Secrets Present - {len(keys)} keys in env - LIVE","category":"Security","type":"Env Keys","source":"Local Env - LIVE","risk":"High" if len(keys) > 3 else "Medium","status":"Active","owner":os.environ.get("USER","unknown"),"model":"os.environ names only","data_access":["Secrets"],"evidence":", ".join(masked) + " | Env keys present does NOT mean leaked - check if .env is tracked / committed.","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":len(keys),"policy_violations":1,"cloud":"On-Prem / Local","region":"local","repo_url":"","scan_id":scan_id})
    return assets

def not_configured_asset(name, category, typ, hint, scan_id):
    return {"name": f"{name} - Not Connected (set {hint})","category":category,"type":typ,"source":"Connector - NOT CONFIGURED","risk":"Low","status":"Not Configured","owner":"unknown","model":"not configured","data_access":[],"evidence":f"Set {hint} in .env to enable LIVE scan. This is a coverage gap, NOT Low risk.","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":0,"policy_violations":0,"cloud":name,"region":"-","repo_url":"","scan_id":scan_id}

def scan_github(scan_id):
    token = os.environ.get("GITHUB_TOKEN","").strip()
    if not token or not requests:
        return [not_configured_asset("GitHub","Repository","GitHub Org/User","GITHUB_TOKEN",scan_id)]
    assets = []
    try:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        r = requests.get("https://api.github.com/user", headers=headers, timeout=10)
        if r.status_code == 401:
            return [{"name": "GitHub - Invalid Token - LIVE","category":"Repository","type":"GitHub Org/User","source":"GitHub API - LIVE","risk":"High","status":"Active","owner":"unknown","model":"github api","data_access":["Source Code"],"evidence":"GitHub API returned 401 - token invalid or expired","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":1,"cloud":"GitHub","region":"-","repo_url":"","scan_id":scan_id}]
        user = r.json() if r.status_code == 200 else {}
        login = user.get("login","unknown")
        assets.append({"name": f"GitHub User: {login} - LIVE","category":"Identity","type":"GitHub User","source":"GitHub API - LIVE","risk":"Low","status":"Active","owner":login,"model":"github api","data_access":["Repo List"],"evidence":f"GitHub user {login}, public_repos={user.get('public_repos')}, private={user.get('total_private_repos')}","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"GitHub","region":"-","repo_url":user.get("html_url",""),"scan_id":scan_id})
        page = 1
        total_repos = 0
        while page <= 3:
            rr = requests.get(f"https://api.github.com/user/repos?per_page=100&page={page}&affiliation=owner,collaborator", headers=headers, timeout=10)
            if rr.status_code != 200: break
            repos = rr.json()
            if not repos: break
            for repo in repos:
                total_repos += 1
                is_public = not repo.get("private", False)
                # FIX: Public repo alone is NOT auto-High. Public + personal = Medium, Public + org / fork = check separately. Only High if we have evidence of secrets (secret scan covers that).
                if is_public:
                    risk = "Medium"
                else:
                    risk = "Low"
                if is_allowlisted(repo.get("full_name","")): risk = "Low"
                assets.append({"name": f"GitHub Repo: {repo.get('full_name')} - {'PUBLIC' if is_public else 'Private'} - LIVE","category":"Repository","type":"GitHub Repo","source":"GitHub API - LIVE","risk":risk,"status":"Allowlisted" if is_allowlisted(repo.get("full_name","")) else "Active","owner":login,"model":repo.get("language") or "unknown","data_access":["Source Code"],"evidence":f"Private={repo.get('private')}, Public={is_public}, Language={repo.get('language')}, DefaultBranch={repo.get('default_branch')}, Pushed={repo.get('pushed_at')} | Public alone is NOT a breach - check secret scan + PII exposure.","first_seen":repo.get("created_at","")[:10] or datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":1 if is_public else 0,"cloud":"GitHub","region":"-","repo_url":repo.get("html_url",""),"scan_id":scan_id})
            if len(repos) < 100: break
            page += 1
    except Exception as e:
        assets.append({"name": "GitHub - API Error - LIVE","category":"Repository","type":"GitHub Org/User","source":"GitHub API - LIVE","risk":"Medium","status":"Active","owner":"unknown","model":"github api","data_access":[],"evidence":f"Error: {str(e)[:180]}","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"GitHub","region":"-","repo_url":"","scan_id":scan_id})
    return assets

def scan_aws(scan_id):
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return [not_configured_asset("AWS","Cloud","AWS Account","AWS_ACCESS_KEY_ID",scan_id)]
    try:
        import boto3
    except Exception:
        return [{"name": "AWS - boto3 not installed - NOT CONFIGURED","category":"Cloud","type":"AWS Account","source":"Connector - NOT CONFIGURED","risk":"Low","status":"Not Configured","owner":"unknown","model":"boto3 missing","data_access":[],"evidence":"pip install boto3 to enable AWS LIVE scan","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":0,"policy_violations":0,"cloud":"AWS","region":"-","repo_url":"","scan_id":scan_id}]
    assets = []
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    try:
        s3 = boto3.client("s3", region_name=region)
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            bname = b.get('Name')
            # FIX: Check tags (owner) + public ACL/policy, not just list
            owner_tag = "unknown - no tags found"
            is_public = False
            try:
                tags = s3.get_bucket_tagging(Bucket=bname).get("TagSet", [])
                owner_tag = ", ".join([f"{t['Key']}={t['Value']}" for t in tags]) or "no tags"
                # Owner = tag Owner/owner if present
                for t in tags:
                    if t['Key'].lower() in ("owner","team","cost-center"):
                        owner_tag = f"{t['Key']}={t['Value']}"
            except Exception:
                pass
            try:
                acl = s3.get_bucket_acl(Bucket=bname)
                for grant in acl.get("Grants", []):
                    if "AllUsers" in str(grant.get("Grantee", {}).get("URI","")) or "AuthenticatedUsers" in str(grant.get("Grantee", {}).get("URI","")):
                        is_public = True
            except Exception:
                pass
            try:
                pol_status = s3.get_bucket_policy_status(Bucket=bname).get("PolicyStatus", {})
                if pol_status.get("IsPublic"):
                    is_public = True
            except Exception:
                pass
            risk = "High" if is_public else ("Medium" if owner_tag.startswith("unknown") else "Low")
            assets.append({"name": f"AWS S3: {bname} - {'PUBLIC' if is_public else 'Private'} - LIVE","category":"Cloud","type":"S3 Bucket","source":"AWS API - LIVE","risk":risk,"status":"Active","owner":owner_tag,"model":"s3","data_access":["Cloud Storage"],"evidence":f"Bucket {bname} created {b.get('CreationDate')} | Tags: {owner_tag} | PublicACL/Policy: {is_public} | Region scanned: {region} only - other regions not scanned (limitation)","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":1 if is_public or owner_tag.startswith("unknown") else 0,"cloud":"AWS","region":region,"repo_url":"","scan_id":scan_id})
    except Exception as e:
        assets.append({"name": "AWS S3 - API Error - LIVE","category":"Cloud","type":"S3 Bucket","source":"AWS API - LIVE","risk":"Medium","status":"Active","owner":"unknown","model":"s3","data_access":[],"evidence":str(e)[:180],"first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"AWS","region":region,"repo_url":"","scan_id":scan_id})
    try:
        ec2 = boto3.client("ec2", region_name=region)
        res = ec2.describe_instances(MaxResults=20)
        count = 0
        for r in res.get("Reservations", []):
            for inst in r.get("Instances", []):
                count += 1
                # Owner from tags
                tags = {t['Key']: t['Value'] for t in inst.get("Tags", [])}
                owner = tags.get("Owner") or tags.get("owner") or tags.get("Team") or "unknown - no Owner tag"
                is_public_ip = bool(inst.get("PublicIpAddress"))
                risk = "High" if is_public_ip and owner.startswith("unknown") else ("Medium" if is_public_ip else "Low")
                assets.append({"name": f"AWS EC2: {inst.get('InstanceId')} ({inst.get('InstanceType')}) - LIVE","category":"Cloud","type":"EC2 Instance","source":"AWS API - LIVE","risk":risk,"status":inst.get("State",{}).get("Name","Active"),"owner":owner,"model":inst.get("InstanceType",""),"data_access":["Compute"],"evidence":f"State={inst.get('State',{}).get('Name')}, PublicIP={inst.get('PublicIpAddress')}, PrivateIP={inst.get('PrivateIpAddress')}, OwnerTag={owner} | Region {region} only","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":1 if is_public_ip else 0,"cloud":"AWS","region":region,"repo_url":"","scan_id":scan_id})
        if count == 0:
            assets.append({"name": "AWS EC2 - No instances in region - LIVE","category":"Cloud","type":"EC2 Instance","source":"AWS API - LIVE","risk":"Low","status":"Active","owner":"unknown","model":"ec2","data_access":[],"evidence":f"No EC2 in {region} (single region scanned)","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":0,"policy_violations":0,"cloud":"AWS","region":region,"repo_url":"","scan_id":scan_id})
    except Exception as e:
        assets.append({"name": "AWS EC2 - API Error - LIVE","category":"Cloud","type":"EC2 Instance","source":"AWS API - LIVE","risk":"Medium","status":"Active","owner":"unknown","model":"ec2","data_access":[],"evidence":str(e)[:180],"first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"AWS","region":region,"repo_url":"","scan_id":scan_id})
    return assets

def scan_placeholders(scan_id):
    out = []
    checks = [("Azure","Cloud","Azure Tenant","AZURE_TENANT_ID"),("GCP","Cloud","GCP Project","GCP_PROJECT"),("VMware vCenter","Infrastructure","VMware vCenter","VCENTER_HOST"),("Active Directory","Identity","Active Directory","AD_DOMAIN"),("Okta","Identity","Okta","OKTA_DOMAIN"),("Microsoft Entra / M365","Identity","Entra / M365","ENTRA_TENANT_ID"),("Google Workspace","SaaS","Google Workspace","GOOGLE_WORKSPACE_DOMAIN"),("Slack","SaaS","Slack Workspace","SLACK_TOKEN")]
    for name, cat, typ, envk in checks:
        if os.environ.get(envk):
            out.append({"name": f"{name} - Configured but connector not yet built - LIVE","category":cat,"type":typ,"source":"Connector - CONFIGURED","risk":"Medium","status":"Active","owner":"unknown","model":"placeholder connector","data_access":[],"evidence":f"{envk} is set, full connector to be built in next iteration. No MFA/orphan check yet - do NOT claim Ghost Identity exists.","first_seen":datetime.now().strftime("%Y-%m-%d"),"last_seen":"now","actions_count":1,"policy_violations":0,"cloud":name,"region":"-","repo_url":"","scan_id":scan_id})
        else:
            out.append(not_configured_asset(name, cat, typ, envk, scan_id))
    return out

# ---------- MAIN SCAN ----------
def run_enterprise_scan(selected_scopes, client_name="Client", consent=False, secret_scan_enabled=False):
    if not consent:
        raise ValueError("Consent required: tick 'I have authorisation to scan this machine / account' before scanning.")
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    prev = load_assets()
    prev_names = set(a["name"] for a in prev)
    # Previous scan snapshot for before/after
    prev_scans = load_scans()
    prev_scan_id = prev_scans[0]["id"] if prev_scans else None
    all_assets = []
    all_assets += scan_system_info(scan_id)
    all_assets += scan_processes(scan_id)
    all_assets += scan_python_env(scan_id)
    all_assets += scan_docker(scan_id)
    all_assets += scan_ports(scan_id)
    all_assets += scan_mcp_configs(scan_id)
    all_assets += scan_env_keys(scan_id)
    if "Repositories" in selected_scopes or "Endpoint / Local" in selected_scopes:
        all_assets += scan_local_repos(scan_id)
        all_assets += scan_secrets(scan_id, enabled=secret_scan_enabled)
    if "Cloud - AWS" in selected_scopes:
        all_assets += scan_aws(scan_id)
    if "Repositories" in selected_scopes:
        all_assets += scan_github(scan_id)
    if any(s in selected_scopes for s in ["Cloud - Azure","Cloud - GCP","On-Prem Infra","SaaS / Identity"]):
        all_assets += scan_placeholders(scan_id)
    seen = set(); dedup = []
    for a in all_assets:
        k = (a["name"], a["source"])
        if k in seen: continue
        seen.add(k); dedup.append(a)
    findings_hash = compute_findings_hash(dedup)
    conn = get_db()
    # FIX: Preserve snapshot, do NOT just DELETE without snapshot. Save current snapshot first.
    for a in dedup:
        conn.execute("INSERT INTO scan_assets (id,scan_id,asset_name,risk,status,snapshot_json,created_at) VALUES (?,?,?,?,?,?,?)",
                     (f"sa-{uuid.uuid4().hex[:8]}", scan_id, a["name"], a["risk"], a["status"], json.dumps(a, default=str), datetime.now().isoformat()))
    conn.execute("DELETE FROM assets")
    for a in dedup:
        conn.execute("INSERT INTO assets (id,name,category,type,source,risk,status,owner,model,data_access,evidence,first_seen,last_seen,actions_count,policy_violations,cloud,region,repo_url,scan_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (f"ast-{uuid.uuid4().hex[:8]}", a["name"], a["category"], a["type"], a["source"], a["risk"], a["status"], a["owner"], a["model"], json.dumps(a["data_access"]), a["evidence"], a["first_seen"], a["last_seen"], a["actions_count"], a["policy_violations"], a["cloud"], a["region"], a["repo_url"], scan_id))
    high = sum(1 for a in dedup if a["risk"] == "High" and a["status"] != "Allowlisted" and "NOT CONFIGURED" not in str(a["source"]))
    live = sum(1 for a in dedup if "LIVE" in a["source"])
    sim = sum(1 for a in dedup if "NOT CONFIGURED" in a["source"])
    _, _, coverage = simple_readiness_score(dedup)
    conn.execute("INSERT INTO scans (id,timestamp,scope,total,high,mode,live_count,simulated_count,client_name,consent,secret_scan_enabled,coverage_pct,findings_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (scan_id, datetime.now().isoformat(), ", ".join(selected_scopes), len(dedup), high, "enterprise-v4.1-fixed", live, sim, client_name, 1 if consent else 0, 1 if secret_scan_enabled else 0, coverage, findings_hash))
    conn.commit(); conn.close()
    new_names = set(a["name"] for a in dedup)
    new_assets = new_names - prev_names
    resolved = prev_names - new_names
    add_ledger_entry("ENTERPRISE_SCAN_COMPLETED", details=f"Scan {scan_id} | Client: {client_name} | Consent: Yes | SecretScan: {'ON' if secret_scan_enabled else 'OFF'} | Scope: {', '.join(selected_scopes)} | Found {len(dedup)} assets ({high} high, allowlisted+NOT CONFIG excluded) | LIVE: {live} | Not Configured: {sim} | Coverage: {coverage}% | New: {len(new_assets)} | Resolved: {len(resolved)} | PrevScan: {prev_scan_id}", severity="Info", findings_hash=findings_hash)
    if new_assets:
        add_ledger_entry("NEW_ASSETS_DETECTED", details=f"New: {', '.join(list(new_assets)[:5])}", severity="Medium", findings_hash=findings_hash)
    for a in dedup:
        if a["policy_violations"] > 0 and a["status"] != "Allowlisted":
            add_ledger_entry("POLICY_VIOLATION_DETECTED", details=f"{a['name'][:80]} has {a['policy_violations']} violation(s) | Category: {a['category']}", severity="High" if a["risk"] == "High" else "Medium", findings_hash=findings_hash)
    return len(dedup), live, high, len(new_assets), coverage, scan_id, prev_scan_id

def get_scan_diff(current_scan_id, prev_scan_id):
    if not prev_scan_id:
        return {"new": [], "resolved": [], "changed_risk": []}
    conn = get_db()
    cur = conn.execute("SELECT asset_name, risk, status FROM scan_assets WHERE scan_id=?", (current_scan_id,)).fetchall()
    prev = conn.execute("SELECT asset_name, risk, status FROM scan_assets WHERE scan_id=?", (prev_scan_id,)).fetchall()
    conn.close()
    cur_map = {r[0]: (r[1], r[2]) for r in cur}
    prev_map = {r[0]: (r[1], r[2]) for r in prev}
    new = [k for k in cur_map if k not in prev_map]
    resolved = [k for k in prev_map if k not in cur_map]
    changed = [k for k in cur_map if k in prev_map and cur_map[k] != prev_map[k]]
    return {"new": new, "resolved": resolved, "changed_risk": changed}


# ---------- PDF COMPAT HELPERS (fpdf 1.7 + fpdf2) ----------
def safe_cell(pdf, w, h, txt):
    txt = safe_pdf_text(txt)
    pdf.set_x(pdf.l_margin)
    # Detect fpdf2 (has new_x) vs fpdf 1.7 (ln param) via signature
    try:
        import inspect as _ins
        if "new_x" in _ins.signature(type(pdf).cell).parameters:
            FPDF.cell(pdf, w, h, txt, new_x="LMARGIN", new_y="NEXT")
        else:
            FPDF.cell(pdf, w, h, txt, ln=1)
    except Exception:
        # Last resort: fpdf 1.7 style
        try:
            FPDF.cell(pdf, w, h, txt, ln=1)
        except Exception:
            pass

def safe_multi(pdf, w, h, txt):
    txt = safe_pdf_text(txt)
    pdf.set_x(pdf.l_margin)
    try:
        import inspect as _ins
        if "new_x" in _ins.signature(type(pdf).multi_cell).parameters:
            FPDF.multi_cell(pdf, w, h, txt, new_x="LMARGIN", new_y="NEXT")
        else:
            FPDF.multi_cell(pdf, w, h, txt)
    except Exception:
        try:
            FPDF.multi_cell(pdf, w, h, txt)
        except Exception:
            pass


def pdf_output_bytes(pdf):
    # fpdf 1.7: output(dest='S') returns str; fpdf2: output() returns bytes/bytearray
    try:
        import inspect as _ins
        params = _ins.signature(type(pdf).output).parameters
        if "dest" in params:
            out = FPDF.output(pdf, dest="S")
        else:
            out = FPDF.output(pdf)
    except Exception:
        try:
            out = pdf.output()
        except Exception:
            out = b""
    if isinstance(out, bytearray):
        return bytes(out)
    if isinstance(out, str):
        return out.encode("latin-1", "ignore")
    if isinstance(out, memoryview):
        return out.tobytes()
    if isinstance(out, bytes):
        return out
    return bytes(out) if out else b""
# ---------- EVIDENCE PACKS ----------
def generate_evidence_pack():
    if FPDF is None:
        return b"FPDF not installed", json.dumps({"error": "fpdf2 missing"})
    assets = load_assets()
    ledger = load_ledger()
    pdf = FPDF(); pdf.add_page(); pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Helvetica","B",16); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,10,safe_pdf_text("Ghost Ledger v4.1 - Evidence Pack (Fixed)"))
    pdf.set_font("Helvetica","",10); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,8,safe_pdf_text(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Classification: Confidential - Internal Use | This is discovery evidence, NOT an audit certification"))
    pdf.ln(3)
    total = len(assets); high = sum(1 for a in assets if a["risk"]=="High" and a["status"]!="Allowlisted" and "NOT CONFIGURED" not in str(a["source"])); med = sum(1 for a in assets if a["risk"]=="Medium"); viol = sum(a["policy_violations"] for a in assets)
    score, level, coverage = simple_readiness_score(assets)
    pdf.set_font("Helvetica","B",12); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,8,safe_pdf_text("1. Executive Summary (Internal)"))
    pdf.set_font("Helvetica","",10); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,6,safe_pdf_text(f"Total Assets: {total}\nHigh Risk (excl. allowlisted/NOT CONFIG): {high} | Medium: {med}\nTotal Policy Violations: {viol}\nInternal Readiness Score: {score}/100 - {level}\nCoverage (LIVE vs NOT CONFIGURED): {coverage}% - NOT CONFIGURED is unknown, not Low risk\nScope: Cloud + On-Prem + Endpoint + Software + Repos + SaaS/Identity + Secrets (opt-in) + Docker + MCP"))
    pdf.ln(2)
    pdf.set_font("Helvetica","B",12); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,8,safe_pdf_text("2. Discovered Assets"))
    pdf.set_font("Helvetica","",9)
    for a in assets:
        safe = safe_pdf_text(f"- [{a['risk']}] {a['name'][:90]} | Cat: {a['category']} | Owner: {a['owner']} | Viol: {a['policy_violations']} | Source: {a['source'][:40]} | Status: {a['status']}")
        pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,5,safe)
    pdf.ln(2)
    pdf.set_font("Helvetica","B",12); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,8,safe_pdf_text("3. Recent Ledger (Full SHA-256 Hash Chain)"))
    pdf.set_font("Helvetica","",8)
    for e in ledger[:20]:
        line = safe_pdf_text(f"[{e['timestamp'][:19]}] {e['action']} | {e['details'][:90]} | Hash: {e['hash'][:16]}... (full hash in JSON)")
        pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,4,line)
    pdf.ln(2)
    pdf.set_font("Helvetica","B",12); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,8,safe_pdf_text("4. Integrity + Limitations"))
    pdf.set_font("Helvetica","",9); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0,5,safe_pdf_text("Append-only full SHA-256 hash chain. Each entry links to previous hash + findings hash. Verify with verify_ledger_chain(). Secrets are never stored, only masked fingerprints (no first4/last4). Command lines are redacted. This pack is evidence for review, NOT a certification of audit-ready. Independence: if the same party fixes and proves, an external auditor must re-perform."))
    out = pdf_output_bytes(pdf)
    ev = {"generated_at": datetime.now().isoformat(),"version":"v4.1-fixed","summary":{"total":total,"high":high,"medium":med,"violations":viol,"score":score,"coverage_pct":coverage},"assets":assets,"ledger_head":ledger[:20]}
    return out, json.dumps(ev, indent=2, default=str)

def generate_evidence_pack_v4(assets, scan_id, client_name="Client"):
    """FIXED v4: set_x before every cell, safe_pdf_text, allowlisted excluded, no hardcoded DONE, before/after diff."""
    from fpdf import FPDF
    rows = build_simple_findings(assets)
    score, level, coverage = simple_readiness_score(assets)
    # Before/after
    scans = load_scans()
    prev_scan_id = None
    for s in scans:
        if s["id"] != scan_id:
            prev_scan_id = s["id"]
            break
    diff = get_scan_diff(scan_id, prev_scan_id) if prev_scan_id else {"new": [], "resolved": [], "changed_risk": []}
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    # Page 1
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 12, safe_pdf_text("Ghost Ledger v4.1 - Evidence Pack"))
    pdf.set_font("Helvetica", "", 11); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 7, safe_pdf_text(f"Client: {client_name}  |  Scan: {scan_id}  |  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"))
    pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 7, safe_pdf_text("Classification: Confidential - For Review Only. NOT an audit certification."))
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 8, safe_pdf_text("In 1 Page: Are we safe to ship AI?"))
    pdf.set_font("Helvetica", "", 11); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 6, safe_pdf_text(f"Internal Readiness Score: {score}/100 - {level}\nCoverage: {coverage}% (LIVE vs NOT CONFIGURED - NOT CONFIGURED is unknown)\nTotal Assets Found: {len(assets)}\nHigh Risk (excl. allowlisted/NOT CONFIG): {sum(1 for a in assets if a.get('risk')=='High' and a.get('status')!='Allowlisted' and 'NOT CONFIGURED' not in str(a.get('source','')))} | Medium: {sum(1 for a in assets if a.get('risk')=='Medium')} | Low: {sum(1 for a in assets if a.get('risk')=='Low')}\nWhat this means: If score is below 80 OR coverage below 80%, do not claim ready. This pack proves what we found, what is still unknown, and what is left. It does NOT certify audit-ready."))
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 7, safe_pdf_text("The 3 Steps We Did"))
    pdf.set_font("Helvetica", "", 11); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 6, safe_pdf_text("1. SCAN - Found Ghost Assets with consent, read-only, secret scan opt-in.\n2. FIX - Fixed Highs first, with owner + date (fix evidence in next scan).\n3. PROVE - Re-scanned. Before/after diff + hash chain proves what changed. No hardcoded DONE."))
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 7, safe_pdf_text("What the Board Needs to Know (Accurate)"))
    pdf.set_font("Helvetica", "", 11); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 6, safe_pdf_text("If a secret is in code AND gives access to personal data, it may trigger DPDP Sec 8(5)/8(6) and GDPR Art 32/33. Secret alone is not automatically a breach. If an AI has no owner, no one is accountable. EU AI Act 7% fine applies ONLY to Art 5 prohibited practices, NOT to missing owner. Missing owner for high-risk systems is up to EUR 15M or 3% (Art 99(4))."))
    # Page 2 - Findings
    pdf.add_page(); pdf.set_font("Helvetica", "B", 14); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 9, safe_pdf_text("Findings - In Simple Language"))
    pdf.set_font("Helvetica", "", 10)
    if not rows:
        pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 6, safe_pdf_text("No High / Medium findings in scoped, allowlisted-excluded assets. Coverage may still be incomplete - check NOT CONFIGURED list."))
    for i, r in enumerate(rows[:20], 1):
        pdf.set_font("Helvetica", "B", 10); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 6, safe_pdf_text(f"{i}. {r['asset']} - {r['risk']} - {r['kind']}"))
        pdf.set_font("Helvetica", "", 10); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 5, safe_pdf_text(f"Why it matters: {r['cost']}\nFix: {r['fix']}\nOwner: {r['owner']} | Fix in: {r['days']} days\nFrameworks: EU AI Act {r['framework']['EU AI Act']} | ISO 42001 {r['framework']['ISO 42001']} | SOC 2 {r['framework']['SOC 2']} | DPDP/GDPR {r['framework']['DPDP / GDPR']}"))
        pdf.ln(2)
    # Page 3 - Roadmap + Checklist (ACTUAL status, not DONE)
    pdf.add_page(); pdf.set_font("Helvetica", "B", 14); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 9, safe_pdf_text("30-Day Fix Roadmap + Before/After"))
    pdf.set_font("Helvetica", "", 11); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 6, safe_pdf_text("Week 1 (Days 1-7): Fix ALL Highs. Rotate keys, make repos/buckets private, assign owners.\nWeek 2 (Days 8-14): Fix Mediums. MFA, logging, branch protection.\nWeek 3-4 (Days 15-30): Build 12 Plans (AI Policy, Data Protection, Incident Response, etc.) + Train team. 12 Plans are NOT DONE until evidence exists.\nDay 30: Re-scan. New Evidence Pack + diff proves fix. Score should be 80+ AND coverage 80+."))
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 7, safe_pdf_text(f"Before/After vs Prev Scan {prev_scan_id or 'none'}"))
    pdf.set_font("Helvetica", "", 11); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 6, safe_pdf_text(f"New assets: {len(diff['new'])} | Resolved: {len(diff['resolved'])} | Risk changed: {len(diff['changed_risk'])}\nNew: {', '.join(diff['new'][:5])}\nResolved: {', '.join(diff['resolved'][:5])}\nIf this is the first scan, before/after is empty - that is expected."))
    pdf.ln(4); pdf.set_font("Helvetica", "B", 14); pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 9, safe_pdf_text("Audit Readiness Checklist - ACTUAL Status"))
    pdf.set_font("Helvetica", "", 11)
    # Actual status logic
    has_assets = len(assets) > 0
    has_findings = len(rows) > 0
    checks = [
        f"Asset Inventory + AI Register - {'PRESENT (this pack lists assets, but AI Register needs owner + use-case for each AI asset - not auto-DONE)' if has_assets else 'MISSING - run scan'}",
        f"Findings + Risk Register - {'PRESENT in this pack (High/Medium only, allowlisted excluded)' if has_findings else 'NO HIGH/MEDIUM FINDINGS in scope - verify coverage'}",
        "Remediation Roadmap - PRESENT in this pack (owners + days)",
        "12 Plans - NOT STARTED until evidence files exist (do NOT mark DONE)",
        "Training + Access Review - NOT STARTED - do quarterly, need attendance + review logs",
        "Retest Evidence - REQUIRES second scan with diff (see Before/After above)",
        "Continuous Monitoring - NOT STARTED - monthly re-scan needed",
    ]
    for c in checks:
        pdf.set_x(pdf.l_margin); safe_cell(pdf, 0, 6, safe_pdf_text(f"- {c}"))
    pdf.ln(4); pdf.set_font("Helvetica", "I", 10); pdf.set_x(pdf.l_margin); safe_multi(pdf, 0, 5, safe_pdf_text("Integrity: Append-only full SHA-256 hash chain. Each scan links to previous hash + findings hash. Secrets are never stored, only masked fingerprints (no secret fragment). Command lines redacted. This pack is evidence for EU AI Act, ISO 42001, NIST AI RMF, SOC 2, DPDP, GDPR review - not a certification."))
    out = pdf_output_bytes(pdf)
    return out

# ---------- UI ----------
st.markdown('<div class="main-header">Ghost Ledger</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Enterprise Scanner v4.1 FIXED &nbsp;|&nbsp; Cloud + On-Prem + Endpoint + MCP + Repos + Secrets (opt-in) + Docker &nbsp;|&nbsp; For Guardrail Sovereign - Discovery evidence, NOT audit certification</div>', unsafe_allow_html=True)
st.markdown('<div class="fix-note"><b>v4.1 fixes:</b> v4 PDF crash fixed, consent + client wired, secret scan opt-in OFF by default, MCP discovery built, process High-by-default fixed, score no longer punishes NOT CONFIGURED, hash chain full SHA-256, no raw cmdline storage, regex boundaries, ISO/DPDP/EU mappings corrected. See header docstring for full list. <b>Honest scope:</b> SaaS/OAuth discovery (140 tools) NOT built - do not claim it.</div>', unsafe_allow_html=True)
assets = load_assets(); ledger = load_ledger(); scans = load_scans(); allow = load_allowlist()

with st.sidebar:
    st.title("Control Panel - v4.1 Fixed")
    st.markdown("### Client + Consent (REQUIRED)")
    client_name = st.text_input("Client name (for Evidence Pack)", placeholder="e.g. Acme Pvt Ltd", value="")
    consent = st.checkbox("I have authorisation to scan this machine / account (read-only). I understand secrets scan is opt-in.", value=False)
    secret_opt_in = st.checkbox("Enable secret scan (opt-in, default OFF) - scans files + git history, capped, PARTIAL", value=False)
    st.caption("Without consent, Scan is blocked. Without secret opt-in, secret scan returns COVERAGE GAP, not 'No secrets'.")
    st.markdown("### Scan Scope")
    scopes = st.multiselect("Select domains", ["Endpoint / Local","Repositories","Cloud - AWS","Cloud - Azure","Cloud - GCP","On-Prem Infra","SaaS / Identity","Software Inventory"], default=["Endpoint / Local","Repositories","Cloud - AWS","Cloud - Azure","Cloud - GCP","On-Prem Infra","SaaS / Identity","Software Inventory"])
    if st.button("Run Enterprise Scan (v4.1)", type="primary", use_container_width=True):
        if not consent:
            st.error("Consent required. Tick the consent checkbox first.")
        elif not client_name.strip():
            st.error("Client name required for Evidence Pack. Enter client name.")
        else:
            with st.spinner("Running v4.1 scan - LIVE + MCP + GitHub + AWS + Docker + Secrets (if opted-in)..."):
                import time; time.sleep(1.0)
                try:
                    total, live, high, newc, coverage, sid, prev_sid = run_enterprise_scan(scopes, client_name=client_name.strip(), consent=consent, secret_scan_enabled=secret_opt_in)
                    st.success(f"Scan done: {total} assets | {live} LIVE | {high} High (excl. allowlisted/NOT CONFIG) | {newc} New | Coverage {coverage}% | ID {sid}")
                except ValueError as ve:
                    st.error(str(ve))
                st.rerun()
    st.markdown("---")
    st.markdown("### Connectors Status")
    for label, key in [("AWS","AWS_ACCESS_KEY_ID"),("Azure","AZURE_TENANT_ID"),("GCP","GCP_PROJECT"),("GitHub","GITHUB_TOKEN"),("Okta","OKTA_DOMAIN"),("VMware","VCENTER_HOST"),("AD","AD_DOMAIN"),("Slack","SLACK_TOKEN")]:
        present = bool(os.environ.get(key))
        st.markdown(f"{'🟢' if present else '⚪'} {label} - {'configured' if present else 'not set - will show NOT CONFIGURED (coverage gap)'}")
    st.caption("Set vars in .env or shell. Never paste secrets in chat. Scanner only reads names, masks values, redacts cmdlines.")
    st.markdown("---")
    st.markdown("### Allowlist")
    al_pat = st.text_input("Pattern to allowlist (substring)", placeholder="CursorUIViewService")
    al_reason = st.text_input("Reason", placeholder="Apple system service")
    if st.button("Add to Allowlist", use_container_width=True):
        if al_pat.strip():
            conn = get_db(); conn.execute("INSERT OR REPLACE INTO allowlist (pattern,reason,created_at) VALUES (?,?,?)", (al_pat.strip(), al_reason or "manual", datetime.now().isoformat())); conn.commit(); conn.close()
            st.success(f"Allowlisted: {al_pat}. Re-scan to apply.")
            st.rerun()
    if allow:
        st.caption("Current allowlist: " + ", ".join([a['pattern'] for a in allow]))
    st.markdown("---")
    st.markdown("### Actions")
    if st.button("Generate Evidence Pack (v4.1 Fixed)", use_container_width=True):
        if not assets:
            st.warning("Run a scan first")
        else:
            # Use last scan id + client from last scan if available
            last_client = scans[0].get("client_name") if scans and scans[0].get("client_name") else (client_name or "Client")
            last_sid = scans[0]["id"] if scans else "scan-unknown"
            try:
                pdf_bytes = generate_evidence_pack_v4(assets, last_sid, client_name=last_client or "Client")
                st.download_button("Download PDF v4.1", data=bytes(pdf_bytes), file_name=f"ghost-ledger-v4.1-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf", mime="application/pdf", use_container_width=True)
                add_ledger_entry("EVIDENCE_PACK_GENERATED", details=f"v4.1 evidence pack exported for {last_client} scan {last_sid}", severity="Info", findings_hash=compute_findings_hash(assets))
            except Exception as e:
                st.error(f"PDF failed: {e} - this should not happen in v4.1, report bug with asset names")
    if st.button("Generate Evidence Pack (v3-style, fixed)", use_container_width=True):
        if not assets:
            st.warning("Run a scan first")
        else:
            pdf_bytes, json_str = generate_evidence_pack()
            st.download_button("Download PDF v3-fixed", data=bytes(pdf_bytes), file_name=f"ghost-ledger-v3-fixed-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf", mime="application/pdf", use_container_width=True)
            st.download_button("Download JSON", data=json_str, file_name=f"ghost-ledger-v3-fixed-{datetime.now().strftime('%Y%m%d-%H%M')}.json", mime="application/json", use_container_width=True)
    if st.button("Verify Ledger Chain", use_container_width=True):
        ok, msg = verify_ledger_chain()
        if ok:
            st.success(msg)
        else:
            st.error(msg)
    if st.button("Archive Current Scan (NOT Delete)", use_container_width=True):
        # FIX: Archive, not Clear All Data. Ledger preserved.
        if assets:
            conn = get_db()
            for a in assets:
                conn.execute("INSERT INTO archive_assets (id,archived_at,scan_id,asset_json) VALUES (?,?,?,?)", (f"arc-{uuid.uuid4().hex[:8]}", datetime.now().isoformat(), a.get("scan_id",""), json.dumps(a, default=str)))
            conn.commit(); conn.close()
            add_ledger_entry("SCAN_ARCHIVED", details=f"Archived {len(assets)} assets, ledger preserved (no delete)", severity="Info")
            st.success(f"Archived {len(assets)} assets. Ledger NOT deleted. Use Archive to keep evidence.")
        else:
            st.info("Nothing to archive.")
    st.markdown("---")
    st.info("**v4.1 mode:** Local + GitHub + AWS + MCP are LIVE when configured. Others show NOT CONFIGURED (coverage gap, not Low risk). No fake data. No secrets stored, only masked fingerprints (no fragment). No raw cmdline.")

if assets:
    c1,c2,c3,c4,c5,c6 = st.columns(6)
    with c1: st.metric("Total Assets", len(assets))
    with c2: st.metric("High Risk", sum(1 for a in assets if a["risk"]=="High" and a["status"]!="Allowlisted" and "NOT CONFIGURED" not in str(a["source"])))
    with c3: st.metric("Policy Violations", sum(a["policy_violations"] for a in assets))
    with c4: st.metric("LIVE Sources", sum(1 for a in assets if "LIVE" in a["source"]))
    with c5: st.metric("Not Configured", sum(1 for a in assets if "NOT CONFIGURED" in a["source"]))
    score, level, coverage = simple_readiness_score(assets)
    with c6: st.metric("Internal Score / Coverage", f"{score} / {coverage}%")
    st.caption(f"Score is INTERNAL prioritisation, NOT audit certification. Level: {level}")
    if scans:
        st.caption(f"Last scan: {scans[0]['timestamp'][:19]} | Client: {scans[0].get('client_name','-')} | Consent: {'Yes' if scans[0].get('consent') else 'No'} | SecretScan: {'ON' if scans[0].get('secret_scan_enabled') else 'OFF'} | Scope: {scans[0]['scope']} | ID: {scans[0]['id']} | Mode: {scans[0]['mode']}")
else:
    st.warning("No assets yet. Enter client name, tick consent, select scope and click **Run Enterprise Scan**.")

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["All Assets","Cloud","Repositories","Secrets & Docker","MCP Servers (NEW)","Risk Analytics","Action Ledger"])

with tab1:
    st.subheader("All Discovered Assets (High first - fixed sort)")
    if assets:
        df = pd.DataFrame([{"Name":a["name"],"Category":a["category"],"Type":a["type"],"Source":a["source"],"Risk":a["risk"],"Status":a["status"],"Owner":a["owner"],"Viol":a["policy_violations"],"Cloud":a["cloud"]} for a in assets])
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.markdown("### Asset Detail")
        for a in assets:
            with st.expander(f"{a['name'][:90]} - {a['risk']} - {a['status']}"):
                st.write(f"**Category:** {a['category']} | **Type:** {a['type']} | **Source:** {a['source']}")
                st.write(f"**Owner:** {a['owner']} | **Model:** {a['model']}")
                st.write(f"**Data Access:** {', '.join(a['data_access']) if a['data_access'] else 'None'}")
                st.write(f"**Evidence (redacted):** {a['evidence'][:500]}")
                st.write(f"**Cloud:** {a['cloud']} | **Region:** {a['region']} | **Repo:** {a['repo_url']}")
    else:
        st.info("Run a scan first.")

with tab2:
    st.subheader("Cloud / On-Prem / SaaS")
    cloud_assets = [a for a in assets if a["category"] in ["Cloud","Infrastructure","Identity","SaaS"]]
    if cloud_assets:
        st.dataframe(pd.DataFrame([{"Name":a["name"],"Source":a["source"],"Risk":a["risk"],"Status":a["status"],"Cloud":a["cloud"],"Owner":a["owner"]} for a in cloud_assets]), use_container_width=True, hide_index=True)
    else:
        st.info("No cloud assets yet.")

with tab3:
    st.subheader("Repositories - Local + GitHub LIVE")
    repo_assets = [a for a in assets if a["category"]=="Repository"]
    if repo_assets:
        st.dataframe(pd.DataFrame([{"Name":a["name"],"Source":a["source"],"Risk":a["risk"],"Owner":a["owner"],"Repo URL":a["repo_url"]} for a in repo_assets]), use_container_width=True, hide_index=True)
        st.caption("Public repo alone is NOT auto-High in v4.1. Check secret scan + PII exposure to decide breach.")
    else:
        st.info("No repos found.")

with tab4:
    st.subheader("Secrets & Docker - LIVE (Opt-in)")
    sec = [a for a in assets if a["category"]=="Security" or "Docker" in a["type"]]
    if sec:
        for a in sec:
            st.markdown(f"**[{a['risk']}] {a['name']}** - {a['source']}")
            st.caption(a["evidence"][:500])
    else:
        st.info("No secret scan results. If secret scan was OFF, this is a coverage gap, NOT 'No secrets found'.")

with tab5:
    st.subheader("MCP Servers - NEW in v4.1 (Claude Desktop / Cursor / VS Code / Windsurf)")
    mcp_assets = [a for a in assets if a["type"]=="MCP Server"]
    if mcp_assets:
        for a in mcp_assets:
            st.markdown(f"**[{a['risk']}] {a['name']}**")
            st.caption(a["evidence"][:500])
            st.write(f"Owner: {a['owner']} | Config: {a['repo_url']}")
    else:
        st.info("No MCP assets. Run a scan - MCP discovery checks global + repo-level configs.")

with tab6:
    st.subheader("Risk Analytics")
    if assets:
        df = pd.DataFrame(assets)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**By Risk (allowlisted + NOT CONFIG excluded from High count in metrics above)**")
            st.bar_chart(df["risk"].value_counts())
        with col2:
            st.markdown("**By Category**")
            st.bar_chart(df["category"].value_counts())
        st.markdown("**By Source**")
        st.bar_chart(df["source"].value_counts().head(10))

with tab7:
    st.subheader("Action Ledger - Full SHA-256 Hash Chain")
    ok, msg = verify_ledger_chain()
    if ok:
        st.success(msg)
    else:
        st.error(msg)
    if ledger:
        for e in ledger[:30]:
            st.markdown(f"`{e['timestamp'][:19]}` **{e['action']}** - {e['details'][:160]} | Hash: `{e['hash'][:16]}...` | Prev: `{e['prev_hash'][:16]}...`")
    else:
        st.info("No ledger entries yet.")
    st.markdown("---")
    st.subheader("Scan History + Before/After")
    if scans:
        st.dataframe(pd.DataFrame([{"ID":s["id"],"Time":s["timestamp"][:19],"Client":s.get("client_name","-"),"Total":s["total"],"High":s["high"],"LIVE":s["live_count"],"Not Config":s["simulated_count"],"Coverage%":s.get("coverage_pct","-")} for s in scans]), use_container_width=True, hide_index=True)
        if len(scans) >= 2:
            diff = get_scan_diff(scans[0]["id"], scans[1]["id"])
            st.markdown(f"**Diff vs prev scan {scans[1]['id']}:** New {len(diff['new'])} | Resolved {len(diff['resolved'])} | Risk changed {len(diff['changed_risk'])}")
            if diff["new"]:
                st.write("New:", diff["new"][:10])
            if diff["resolved"]:
                st.write("Resolved:", diff["resolved"][:10])

st.markdown("---")
st.caption("Ghost Ledger v4.1 FIXED • Discovery evidence only • Not a production auditor • Not audit certification • Independence: fixer cannot certify own fixes - external auditor must re-perform • Verify mappings against primary texts: EU AI Act Reg (EU) 2024/1689 Art 5/9/15/99, ISO/IEC 42001:2023 Annex A, DPDP Act 2023 Sec 8(5)/8(6), GDPR Art 32/33")
