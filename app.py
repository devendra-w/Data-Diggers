from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from functools import wraps
import bcrypt, jwt, datetime, random

app = Flask(__name__)
CORS(app)
SECRET = "datadiggers_bank_2026"

# ─────────────────────────────────────────
#  IN-MEMORY DATABASE
# ─────────────────────────────────────────
users = []
logs  = []
transactions = []

ROLES = {
    "super_admin":  {"label": "Super Admin",  "color": "gold",   "desc": "Full system control"},
    "bank_manager": {"label": "Bank Manager", "color": "purple", "desc": "Branch & user oversight"},
    "teller":       {"label": "Teller",       "color": "blue",   "desc": "Process transactions"},
    "auditor":      {"label": "Auditor",       "color": "teal",  "desc": "Read-only audit access"},
    "customer":     {"label": "Customer",     "color": "green",  "desc": "Own account only"},
}

PERMISSIONS = {
    "super_admin":  ["view_all", "manage_users", "approve_loans", "view_audit", "process_tx", "system_config", "view_reports", "freeze_accounts"],
    "bank_manager": ["view_all", "manage_users", "approve_loans", "view_audit", "process_tx", "view_reports", "freeze_accounts"],
    "teller":       ["process_tx", "view_own", "view_reports"],
    "auditor":      ["view_all", "view_audit", "view_reports"],
    "customer":     ["view_own", "process_tx"],
}

def seed():
    accounts_data = [
        ("superadmin", "super123",  "super_admin",  "Super Administrator",  "HDFC001", 9999999.00),
        ("manager1",   "mgr123",    "bank_manager", "Ravi Sharma",          "HDFC002", 850000.00),
        ("teller1",    "teller123", "teller",       "Priya Patel",          "HDFC003", 45000.00),
        ("auditor1",   "audit123",  "auditor",      "Arjun Mehta",          "HDFC004", 62000.00),
        ("alice",      "alice123",  "customer",     "Alice Fernandez",      "HDFC005", 125000.50),
        ("bob",        "bob123",    "customer",     "Bob Krishnan",         "HDFC006", 78500.00),
        ("carol",      "carol123",  "customer",     "Carol Nair",           "HDFC007", 210000.75),
    ]
    for un, pw, role, fullname, acc, bal in accounts_data:
        users.append({
            "username": un,
            "password": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
            "role": role,
            "fullname": fullname,
            "email": f"{un}@hdfcbank.in",
            "account_no": acc,
            "balance": bal,
            "status": "active",
            "joined": "2024-01-15",
        })

    # seed some transactions
    tx_data = [
        ("HDFC005", "HDFC006", 5000.00,  "Transfer",  "Rent payment"),
        ("HDFC006", "HDFC007", 12000.00, "Transfer",  "Invoice #INV-2024"),
        ("HDFC007", "HDFC005", 3500.00,  "Transfer",  "Reimbursement"),
        ("HDFC005", "HDFC001", 10000.00, "Loan EMI",  "Home Loan EMI"),
        ("HDFC006", "HDFC001", 8500.00,  "Loan EMI",  "Car Loan EMI"),
    ]
    for i, (frm, to, amt, typ, note) in enumerate(tx_data):
        transactions.append({
            "id": f"TXN{1000+i}",
            "from": frm,
            "to": to,
            "amount": amt,
            "type": typ,
            "note": note,
            "status": "completed",
            "time": f"2024-12-{10+i} 14:{30+i}:00"
        })

seed()

def log(kind, msg):
    logs.insert(0, {
        "kind": kind,
        "msg":  msg,
        "time": datetime.datetime.now().strftime("%H:%M:%S")
    })

def has_perm(role, perm):
    return perm in PERMISSIONS.get(role, [])

# ─────────────────────────────────────────
#  AUTH DECORATOR
# ─────────────────────────────────────────
def auth(required_perm=None, admin_roles=None):
    def wrapper(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                log("danger", "Blocked: missing token")
                return jsonify(error="Not authenticated"), 401
            try:
                payload = jwt.decode(token, SECRET, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify(error="Session expired"), 401
            except Exception:
                return jsonify(error="Invalid token"), 401

            if required_perm and not has_perm(payload["role"], required_perm):
                log("danger", f"403 — {payload['username']} [{payload['role']}] tried to access {required_perm}")
                return jsonify(error="Insufficient permissions"), 403

            if admin_roles and payload["role"] not in admin_roles:
                log("danger", f"403 — {payload['username']} blocked from admin route")
                return jsonify(error="Access denied"), 403

            request.me = payload
            return fn(*args, **kwargs)
        return inner
    return wrapper

# ─────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────

@app.post("/api/login")
def api_login():
    body = request.json or {}
    un   = body.get("username", "").strip().lower()
    pw   = body.get("password", "")
    user = next((u for u in users if u["username"] == un), None)
    if not user or not bcrypt.checkpw(pw.encode(), user["password"]):
        log("danger", f"Failed login attempt: {un}")
        return jsonify(error="Wrong username or password"), 401
    if user.get("status") == "frozen":
        log("danger", f"Frozen account login attempt: {un}")
        return jsonify(error="Account is frozen. Contact bank manager."), 403
    token = jwt.encode(
        {"username": un, "role": user["role"],
         "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=4)},
        SECRET, algorithm="HS256"
    )
    log("success", f"Login: {user['fullname']} [{user['role'].upper()}]")
    return jsonify(
        token=token, username=un, role=user["role"],
        fullname=user["fullname"], email=user["email"],
        account_no=user["account_no"]
    )

@app.post("/api/register")
def api_register():
    body = request.json or {}
    un   = body.get("username", "").strip().lower()
    pw   = body.get("password", "")
    fn   = body.get("fullname", un.title())
    if not un or not pw:
        return jsonify(error="Username and password required"), 400
    if any(u["username"] == un for u in users):
        return jsonify(error="Username already taken"), 409
    acc_no = f"HDFC{random.randint(100, 999)}"
    users.append({
        "username": un,
        "password": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
        "role": "customer",
        "fullname": fn,
        "email": f"{un}@hdfcbank.in",
        "account_no": acc_no,
        "balance": 10000.00,
        "status": "active",
        "joined": datetime.datetime.now().strftime("%Y-%m-%d"),
    })
    log("success", f"New customer registered: {un} [Account: {acc_no}]")
    return jsonify(ok=True, message=f"Account created for {un}")

@app.get("/api/me")
@auth()
def api_me():
    u = next(u for u in users if u["username"] == request.me["username"])
    return jsonify(
        username=u["username"], role=u["role"], fullname=u["fullname"],
        email=u["email"], account_no=u["account_no"],
        balance=u["balance"], status=u["status"], joined=u["joined"],
        permissions=PERMISSIONS.get(u["role"], [])
    )

@app.get("/api/stats")
@auth()
def api_stats():
    me = request.me
    if has_perm(me["role"], "view_all"):
        total_bal = sum(u["balance"] for u in users)
        total_tx  = len(transactions)
        blocked   = sum(1 for l in logs if l["kind"] == "danger")
    else:
        u = next(u for u in users if u["username"] == me["username"])
        total_bal = u["balance"]
        total_tx  = sum(1 for t in transactions if t["from"] == u["account_no"] or t["to"] == u["account_no"])
        blocked   = 0
    return jsonify(
        total_users=len(users),
        total_balance=total_bal,
        total_transactions=total_tx,
        blocked=blocked,
        recent=logs[:8],
        role=me["role"]
    )

@app.get("/api/accounts")
@auth(required_perm="view_all")
def api_accounts():
    return jsonify(accounts=[
        {"username": u["username"], "fullname": u["fullname"],
         "role": u["role"], "email": u["email"],
         "account_no": u["account_no"], "balance": u["balance"],
         "status": u["status"]}
        for u in users
    ])

@app.get("/api/my-account")
@auth()
def api_my_account():
    u = next(u for u in users if u["username"] == request.me["username"])
    my_tx = [t for t in transactions if t["from"] == u["account_no"] or t["to"] == u["account_no"]]
    return jsonify(
        account_no=u["account_no"], balance=u["balance"],
        fullname=u["fullname"], status=u["status"],
        transactions=my_tx[-10:]
    )

@app.get("/api/transactions")
@auth(required_perm="view_reports")
def api_transactions():
    return jsonify(transactions=transactions)

@app.post("/api/transfer")
@auth(required_perm="process_tx")
def api_transfer():
    body   = request.json or {}
    frm_acc = body.get("from_account", "")
    to_acc  = body.get("to_account", "")
    amount  = float(body.get("amount", 0))
    note    = body.get("note", "Transfer")
    me      = request.me

    if amount <= 0:
        return jsonify(error="Invalid amount"), 400

    sender   = next((u for u in users if u["account_no"] == frm_acc), None)
    receiver = next((u for u in users if u["account_no"] == to_acc), None)

    if not sender or not receiver:
        return jsonify(error="Account not found"), 404

    # customers can only transfer from their own account
    if me["role"] == "customer" and sender["username"] != me["username"]:
        log("danger", f"Unauthorized transfer attempt by {me['username']}")
        return jsonify(error="You can only transfer from your own account"), 403

    if sender["balance"] < amount:
        return jsonify(error="Insufficient balance"), 400

    sender["balance"]   -= amount
    receiver["balance"] += amount

    tx = {
        "id": f"TXN{1000 + len(transactions)}",
        "from": frm_acc,
        "to": to_acc,
        "amount": amount,
        "type": "Transfer",
        "note": note,
        "status": "completed",
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    transactions.insert(0, tx)
    log("success", f"Transfer ₹{amount:,.2f}: {frm_acc} → {to_acc} (by {me['username']})")
    return jsonify(ok=True, transaction=tx)

@app.post("/api/freeze-account")
@auth(required_perm="freeze_accounts")
def api_freeze():
    target_un = (request.json or {}).get("username", "")
    action    = (request.json or {}).get("action", "freeze")
    me        = request.me
    u = next((u for u in users if u["username"] == target_un), None)
    if not u:
        return jsonify(error="User not found"), 404
    u["status"] = "frozen" if action == "freeze" else "active"
    log("danger" if action == "freeze" else "success",
        f"Account {action}d: {target_un} (by {me['username']})")
    return jsonify(ok=True, message=f"Account {action}d")

@app.post("/api/admin/add-user")
@auth(admin_roles=["super_admin", "bank_manager"])
def api_add_user():
    body = request.json or {}
    un   = body.get("username", "").strip().lower()
    pw   = body.get("password", "")
    role = body.get("role", "customer")
    fn   = body.get("fullname", un.title())
    me   = request.me

    if role not in ROLES:
        return jsonify(error="Invalid role"), 400
    # bank_manager cannot create super_admin
    if me["role"] == "bank_manager" and role == "super_admin":
        return jsonify(error="Bank managers cannot create Super Admin accounts"), 403
    if not un or not pw:
        return jsonify(error="Username and password required"), 400
    if any(u["username"] == un for u in users):
        return jsonify(error="Username already exists"), 409

    acc_no = f"HDFC{random.randint(100, 999)}"
    users.append({
        "username": un,
        "password": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
        "role": role,
        "fullname": fn,
        "email": f"{un}@hdfcbank.in",
        "account_no": acc_no,
        "balance": float(body.get("initial_balance", 10000)),
        "status": "active",
        "joined": datetime.datetime.now().strftime("%Y-%m-%d"),
    })
    log("success", f"User added: {un} [{role.upper()}] by {me['username']}")
    return jsonify(ok=True, message=f"User '{un}' created with account {acc_no}")

@app.post("/api/admin/delete-user")
@auth(admin_roles=["super_admin"])
def api_delete_user():
    global users
    target = (request.json or {}).get("username", "")
    me     = request.me["username"]
    if target == me:
        return jsonify(error="Cannot delete yourself"), 400
    before = len(users)
    users  = [u for u in users if u["username"] != target]
    if len(users) == before:
        return jsonify(error="User not found"), 404
    log("danger", f"User deleted: {target} (by {me})")
    return jsonify(ok=True, message=f"User '{target}' deleted")

@app.post("/api/admin/change-role")
@auth(admin_roles=["super_admin"])
def api_change_role():
    body   = request.json or {}
    target = body.get("username", "")
    role   = body.get("role", "")
    me     = request.me["username"]
    if role not in ROLES:
        return jsonify(error="Invalid role"), 400
    for u in users:
        if u["username"] == target:
            u["role"] = role
            log("success", f"Role changed: {target} → {role.upper()} (by {me})")
            return jsonify(ok=True, message=f"{target} is now {role}")
    return jsonify(error="User not found"), 404

@app.get("/api/audit-logs")
@auth(required_perm="view_audit")
def api_audit_logs():
    return jsonify(logs=logs)

@app.get("/api/loan-applications")
@auth(required_perm="approve_loans")
def api_loans():
    # mock loan data
    return jsonify(loans=[
        {"id": "LN001", "applicant": "alice", "amount": 500000, "type": "Home Loan", "status": "pending", "date": "2024-12-01"},
        {"id": "LN002", "applicant": "bob",   "amount": 150000, "type": "Car Loan",  "status": "approved", "date": "2024-11-28"},
        {"id": "LN003", "applicant": "carol", "amount": 50000,  "type": "Personal",  "status": "pending", "date": "2024-12-10"},
    ])

@app.post("/api/approve-loan")
@auth(required_perm="approve_loans")
def api_approve_loan():
    body   = request.json or {}
    loan_id = body.get("loan_id")
    action  = body.get("action", "approve")
    me      = request.me["username"]
    log("success" if action == "approve" else "danger",
        f"Loan {loan_id} {action}d by {me}")
    return jsonify(ok=True, message=f"Loan {loan_id} {action}d")


# ─────────────────────────────────────────
#  FRONTEND
# ─────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VaultSecure Banking — RBAC Demo</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Mono:wght@400;500&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

:root {
  --bg:       #060a10;
  --bg2:      #0c1220;
  --bg3:      #111827;
  --border:   #1e2d45;
  --border2:  #263548;
  --text:     #e8edf5;
  --muted:    #6b7f99;
  --faint:    #3a4a5e;

  --gold:     #d4a843;
  --gold2:    #f0c060;
  --blue:     #3b7dd8;
  --blue2:    #5b9df0;
  --green:    #2dbd7e;
  --green2:   #4dd999;
  --red:      #e05252;
  --red2:     #ff7070;
  --purple:   #8b5cf6;
  --teal:     #14b8a6;

  --font-display: "DM Serif Display", serif;
  --font-ui:      "Outfit", sans-serif;
  --font-mono:    "DM Mono", monospace;
}

body {
  font-family: var(--font-ui);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}

/* scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }

/* ── PAGE MANAGER ── */
.page    { display:none; }
.page.on { display:flex; }

/* ═══════════════════════════════
   LOGIN PAGE — Meridian / Northstar
═══════════════════════════════ */
#pgLogin {
  min-height: 100vh;
  align-items: center;
  justify-content: center;
  background:
    radial-gradient(ellipse 90% 55% at 50% -5%, rgba(42,90,68,0.30) 0%, transparent 65%),
    radial-gradient(ellipse 50% 40% at 85% 95%, rgba(20,50,90,0.20) 0%, transparent 60%),
    linear-gradient(170deg, #0b1c16 0%, #091422 55%, #0b1c16 100%);
  position: relative;
  overflow: hidden;
}
#pgLogin::before {
  content: "";
  position: absolute; inset: 0;
  background-image:
    linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px);
  background-size: 52px 52px;
  pointer-events: none;
}
#pgLogin::after {
  content: "✦";
  position: absolute;
  bottom: 36px; right: 52px;
  font-size: 26px;
  color: rgba(78,160,110,0.22);
  pointer-events: none;
}

.login-center {
  position: relative; z-index: 1;
  width: 100%;
  max-width: 460px;
  padding: 20px 16px;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.ns-logo {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 18px;
}

.ns-star {
  width: 62px; height: 62px;
  margin-bottom: 12px;
  filter: drop-shadow(0 0 14px rgba(78,160,110,0.35));
}

.ns-brand {
  display: flex;
  align-items: baseline;
  gap: 7px;
  letter-spacing: 3.5px;
  text-transform: uppercase;
  font-size: 14px;
  font-weight: 700;
}
.ns-brand .word1 { color: #b8d4bc; font-weight: 700; }
.ns-brand .word2 { color: var(--green2); font-weight: 300; letter-spacing: 5px; font-size: 13px; }

.ns-title {
  text-align: center;
  margin-bottom: 6px;
  font-size: 21px;
  font-weight: 800;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text);
}
.ns-subtitle {
  text-align: center;
  font-size: 14px;
  color: var(--muted);
  margin-bottom: 28px;
  font-weight: 300;
}

.lcard {
  width: 100%;
  background: rgba(8, 18, 30, 0.88);
  border: 1px solid rgba(255,255,255,0.07);
  border-radius: 20px;
  padding: 30px 30px 26px;
  backdrop-filter: blur(16px);
  box-shadow:
    0 40px 80px rgba(0,0,0,0.55),
    0 0 0 1px rgba(78,160,110,0.06),
    inset 0 1px 0 rgba(255,255,255,0.04);
}

.lcard-title { display:none; }
.lcard-sub   { display:none; }

.ns-security-note {
  display: flex; align-items: flex-start; gap: 9px;
  padding: 10px 14px;
  background: rgba(78,160,110,0.06);
  border: 1px solid rgba(78,160,110,0.12);
  border-radius: 8px;
  margin-top: 14px;
  font-size: 11px; color: #7aab88; line-height: 1.6;
}
.ns-security-note .shield { font-size: 14px; flex-shrink:0; margin-top:1px; }

/* tabs */
.tabs { display:flex; background: var(--bg2); border: 1px solid var(--border); border-radius:8px; padding:4px; margin-bottom:22px; }
.tab  { flex:1; text-align:center; padding:8px; border-radius:6px; font-size:13px; font-weight:600; cursor:pointer; color: var(--muted); transition:.2s; font-family: var(--font-ui); }
.tab.active { background: linear-gradient(135deg, var(--gold), var(--gold2)); color: #0a0600; }

.tp { display:none; }
.tp.active { display:block; }

/* quick buttons */
.quick { display:grid; grid-template-columns:1fr 1fr 1fr; gap:6px; margin-bottom:18px; }
.qb {
  padding: 7px 4px; font-size: 10px; font-weight: 700;
  border-radius: 50px; cursor: pointer; border: 1px solid;
  transition: .2s; letter-spacing: 0.3px; text-align: center;
  font-family: var(--font-ui);
}
.qb.sa { background:rgba(212,168,67,.1); border-color:rgba(212,168,67,.35); color:var(--gold2); }
.qb.sa:hover { background:rgba(212,168,67,.2); }
.qb.mg { background:rgba(139,92,246,.1); border-color:rgba(139,92,246,.35); color:#c4b5fd; }
.qb.mg:hover { background:rgba(139,92,246,.2); }
.qb.tl { background:rgba(59,125,216,.1); border-color:rgba(59,125,216,.35); color:var(--blue2); }
.qb.tl:hover { background:rgba(59,125,216,.2); }
.qb.au { background:rgba(20,184,166,.1); border-color:rgba(20,184,166,.35); color:#5eead4; }
.qb.au:hover { background:rgba(20,184,166,.2); }
.qb.cu { background:rgba(45,189,126,.1); border-color:rgba(45,189,126,.35); color:var(--green2); }
.qb.cu:hover { background:rgba(45,189,126,.2); }

/* form */
.fg { margin-bottom:14px; }
.fg label { display:block; font-size:10px; color:var(--muted); margin-bottom:6px; font-weight:700; letter-spacing:1px; text-transform:uppercase; }
.fg input, .fg select {
  width:100%; padding:13px 20px;
  background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.10);
  border-radius:50px; color: var(--text); font-size:14px;
  font-family: var(--font-ui); outline:none; transition:border-color .2s;
}
.fg input:focus, .fg select:focus { border-color: rgba(78,160,110,0.6); }
.fg select option { background: var(--bg3); }
.fg .input-wrap { position:relative; }
.fg .input-wrap input { padding-right:46px; }
.fg .pw-eye {
  position:absolute; right:18px; top:50%; transform:translateY(-50%);
  cursor:pointer; color:var(--muted); font-size:15px;
  user-select:none; transition:color .2s;
}
.fg .pw-eye:hover { color:var(--text); }

/* login button — green pill */
.btn-main {
  width:100%; padding:14px;
  background: linear-gradient(135deg, #2e7d52, #3da86e);
  color: white; font-size:14px; font-weight:700;
  border:none; border-radius:50px; cursor:pointer; transition:.2s;
  font-family: var(--font-ui); letter-spacing: 0.5px;
}
.btn-main:hover { opacity:.9; transform:translateY(-1px); box-shadow:0 8px 24px rgba(45,189,126,0.25); }
.btn-main:disabled { background: var(--bg3); color: var(--muted); cursor:not-allowed; transform:none; box-shadow:none; }

.fm { font-size:12px; margin-top:10px; min-height:16px; text-align:center; }
.fm.err { color: var(--red2); }
.fm.ok  { color: var(--green2); }

.role-chip {
  display:inline-block; padding:2px 9px;
  border-radius:999px; font-size:10px; font-weight:700;
  letter-spacing: 0.4px; text-transform: uppercase; border:1px solid;
}
.role-chip.super_admin  { background:rgba(212,168,67,.15);  color:var(--gold2);  border-color:rgba(212,168,67,.25); }
.role-chip.bank_manager { background:rgba(139,92,246,.15);  color:#c4b5fd;        border-color:rgba(139,92,246,.25); }
.role-chip.teller       { background:rgba(59,125,216,.15);  color:var(--blue2);  border-color:rgba(59,125,216,.25); }
.role-chip.auditor      { background:rgba(20,184,166,.15);  color:#5eead4;        border-color:rgba(20,184,166,.25); }
.role-chip.customer     { background:rgba(45,189,126,.15);  color:var(--green2); border-color:rgba(45,189,126,.25); }

@media (max-width:520px) {
  .login-center { padding:16px 12px; }
  .lcard { padding:24px 18px 20px; border-radius:14px; }
}

/* ═══════════════════════════════
   APP PAGE
═══════════════════════════════ */
#pgApp { flex-direction:column; min-height:100vh; }

.topbar {
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 0 24px;
  height: 56px;
  display: flex; align-items: center; justify-content: space-between;
  position: sticky; top:0; z-index:50;
}

.tlogo {
  display: flex; align-items: center; gap: 10px;
}

.tlogo-icon {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, var(--gold), var(--gold2));
  border-radius: 7px;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px;
}

.tlogo-name {
  font-family: var(--font-display);
  font-size: 17px;
  color: var(--gold2);
}

.tright { display:flex; align-items:center; gap:14px; }
.tuser { font-size:13px; color: var(--muted); }
.tuser strong { color: var(--text); font-weight:600; }

.rpill {
  font-size: 10px; font-weight: 700;
  padding: 3px 10px; border-radius:999px;
  letter-spacing: .6px; text-transform: uppercase;
}
.rpill.super_admin  { background:rgba(212,168,67,.15);  color:var(--gold2);  border:1px solid rgba(212,168,67,.3); }
.rpill.bank_manager { background:rgba(139,92,246,.15);  color:#c4b5fd;        border:1px solid rgba(139,92,246,.3); }
.rpill.teller       { background:rgba(59,125,216,.15);  color:var(--blue2);  border:1px solid rgba(59,125,216,.3); }
.rpill.auditor      { background:rgba(20,184,166,.15);  color:#5eead4;        border:1px solid rgba(20,184,166,.3); }
.rpill.customer     { background:rgba(45,189,126,.15);  color:var(--green2); border:1px solid rgba(45,189,126,.3); }

.btn-out {
  font-size:12px; font-weight:600; padding:6px 14px;
  background:transparent; color: var(--muted);
  border:1px solid var(--border); border-radius:6px; cursor:pointer; transition:.2s;
  font-family: var(--font-ui);
}
.btn-out:hover { border-color: var(--red); color: var(--red2); }

.app-body { display:flex; flex:1; min-height:calc(100vh - 56px); }

/* ── SIDEBAR ── */
.sidebar {
  width: 216px; flex-shrink:0;
  background: var(--bg2);
  border-right: 1px solid var(--border);
  padding: 20px 0;
  display: flex; flex-direction: column;
}

.slabel {
  font-size: 9px; font-weight: 700; color: var(--faint);
  letter-spacing: 1.2px; text-transform: uppercase;
  padding: 10px 20px 4px;
}

.sl {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 20px; font-size: 13px; color: var(--muted);
  cursor: pointer; transition: all .15s;
  border-left: 2px solid transparent;
  border-radius: 0 6px 6px 0;
  margin: 1px 8px 1px 0;
}

.sl:hover  { background:rgba(255,255,255,.03); color: var(--text); }
.sl.active { background:rgba(212,168,67,.07); color:var(--gold2); border-left-color:var(--gold); }
.sl.locked { color: var(--faint); cursor:not-allowed; font-size:12px; }
.sl.locked:hover { background:none; }

.sl-icon { width:18px; text-align:center; font-size:14px; }

/* ── MAIN ── */
.main { flex:1; padding:28px; overflow-y:auto; }

.view { display:none; }
.view.active { display:block; animation: fadeUp .25s ease; }
@keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1} }

.vtitle {
  display: flex; align-items: baseline; gap: 12px;
  margin-bottom: 24px;
}

.vtitle h2 {
  font-family: var(--font-display);
  font-size: 26px;
  color: var(--text);
}

.vtitle small {
  font-size: 13px; color: var(--muted);
  font-family: var(--font-ui);
}

/* stats grid */
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 14px;
  margin-bottom: 24px;
}

.sbox {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 18px;
  position: relative;
  overflow: hidden;
}

.sbox::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
}

.sbox.gold::before  { background: linear-gradient(90deg, var(--gold), var(--gold2)); }
.sbox.blue::before  { background: linear-gradient(90deg, var(--blue), var(--blue2)); }
.sbox.green::before { background: linear-gradient(90deg, var(--green), var(--green2)); }
.sbox.red::before   { background: linear-gradient(90deg, var(--red), var(--red2)); }

.sval { font-size:28px; font-weight:800; line-height:1; margin-bottom:6px; }
.sval.gold  { color: var(--gold2); }
.sval.blue  { color: var(--blue2); }
.sval.green { color: var(--green2); }
.sval.red   { color: var(--red2); }
.slbl { font-size:11px; color: var(--muted); letter-spacing:.3px; }

/* cards */
.card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 18px;
  overflow: hidden;
}

.chead {
  padding: 14px 20px;
  border-bottom: 1px solid var(--border);
  font-size: 13px; font-weight: 600; color: var(--muted);
  display: flex; align-items: center; justify-content: space-between;
  letter-spacing: 0.3px;
}

.cpad { padding: 18px 20px; }

/* table */
table { width:100%; border-collapse:collapse; font-size:13px; }
th {
  padding: 10px 16px;
  text-align:left; font-size:10px; font-weight:700;
  color: var(--faint); letter-spacing:.8px; text-transform:uppercase;
  border-bottom: 1px solid var(--border);
}
td { padding: 11px 16px; border-bottom: 1px solid rgba(30,45,69,.5); color: var(--text); }
tr:last-child td { border-bottom:none; }
tbody tr:hover td { background:rgba(255,255,255,.02); }

/* badges */
.badge {
  display:inline-block; padding:2px 9px;
  border-radius:999px; font-size:10px; font-weight:700;
  letter-spacing: 0.4px; text-transform: uppercase;
}
.badge.super_admin  { background:rgba(212,168,67,.15);  color:var(--gold2);  border:1px solid rgba(212,168,67,.25); }
.badge.bank_manager { background:rgba(139,92,246,.15);  color:#c4b5fd;        border:1px solid rgba(139,92,246,.25); }
.badge.teller       { background:rgba(59,125,216,.15);  color:var(--blue2);  border:1px solid rgba(59,125,216,.25); }
.badge.auditor      { background:rgba(20,184,166,.15);  color:#5eead4;        border:1px solid rgba(20,184,166,.25); }
.badge.customer     { background:rgba(45,189,126,.15);  color:var(--green2); border:1px solid rgba(45,189,126,.25); }
.badge.active       { background:rgba(45,189,126,.12); color:var(--green2); border:1px solid rgba(45,189,126,.25); }
.badge.frozen       { background:rgba(224,82,82,.12);  color:var(--red2);   border:1px solid rgba(224,82,82,.25); }
.badge.completed    { background:rgba(45,189,126,.1);  color:var(--green2); }
.badge.pending      { background:rgba(212,168,67,.1);  color:var(--gold2); }
.badge.approved     { background:rgba(45,189,126,.1);  color:var(--green2); }
.badge.PDF  { background:rgba(224,82,82,.1); color:var(--red2); }

/* logs */
.li {
  display:flex; align-items:flex-start; gap:12px;
  padding:11px 20px; border-bottom:1px solid rgba(30,45,69,.4);
  font-size:13px;
}
.li:last-child { border-bottom:none; }
.ld { width:7px; height:7px; border-radius:50%; margin-top:5px; flex-shrink:0; }
.ld.success { background:var(--green); box-shadow:0 0 6px var(--green); }
.ld.danger  { background:var(--red);   box-shadow:0 0 6px var(--red); }
.lt { font-size:10px; color:var(--faint); flex-shrink:0; white-space:nowrap; font-family:var(--font-mono); margin-top:1px; }
.lm { color:var(--muted); flex:1; }
.lm.danger  { color:#fca5a5; }
.lm.success { color:#86efac; }

/* profile rows */
.pr { display:flex; justify-content:space-between; align-items:center; padding:12px 20px; border-bottom:1px solid rgba(30,45,69,.4); font-size:13px; }
.pr:last-child { border-bottom:none; }
.pk { color:var(--muted); font-weight:600; font-size:12px; }
.pv { color:var(--text); font-family:var(--font-mono); font-size:12px; }

/* account balance display */
.balance-display {
  text-align: center;
  padding: 32px 20px;
  border-bottom: 1px solid var(--border);
}
.balance-label { font-size:11px; color:var(--muted); letter-spacing:1px; text-transform:uppercase; margin-bottom:8px; }
.balance-amount {
  font-family: var(--font-display);
  font-size: 44px;
  color: var(--gold2);
  margin-bottom: 8px;
}
.balance-acc { font-size:12px; color:var(--faint); font-family:var(--font-mono); }

/* permission matrix */
.yes { color:var(--green2); font-weight:700; text-align:center; }
.no  { color:var(--faint); text-align:center; }

/* action buttons */
.act { font-size:11px; font-weight:600; padding:4px 10px; border-radius:5px; cursor:pointer; border:1px solid; transition:.15s; font-family:var(--font-ui); }
.act.p { background:rgba(59,125,216,.1); color:var(--blue2); border-color:rgba(59,125,216,.3); }
.act.p:hover { background:rgba(59,125,216,.25); }
.act.r { background:rgba(224,82,82,.1); color:var(--red2); border-color:rgba(224,82,82,.3); }
.act.r:hover { background:rgba(224,82,82,.25); }
.act.g { background:rgba(45,189,126,.1); color:var(--green2); border-color:rgba(45,189,126,.3); }
.act.g:hover { background:rgba(45,189,126,.25); }
.act.y { background:rgba(212,168,67,.1); color:var(--gold2); border-color:rgba(212,168,67,.3); }
.act.y:hover { background:rgba(212,168,67,.25); }

/* transfer form */
.tx-form { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
.tx-form .full { grid-column:1/-1; }
.btn-transfer {
  padding:11px 24px;
  background: linear-gradient(135deg, var(--blue), var(--blue2));
  color:white; border:none; border-radius:8px;
  font-size:13px; font-weight:700; cursor:pointer; transition:.2s;
  font-family:var(--font-ui);
}
.btn-transfer:hover { opacity:.9; }

/* add user form */
.add-row { display:flex; gap:8px; flex-wrap:wrap; align-items:flex-end; }
.add-row input, .add-row select {
  flex:1; min-width:90px; padding:9px 11px;
  background:var(--bg); border:1px solid var(--border);
  border-radius:7px; color:var(--text); font-size:13px;
  font-family:var(--font-ui); outline:none;
}
.add-row input:focus, .add-row select:focus { border-color:var(--gold); }
.add-row select option { background:var(--bg3); }
.btn-add {
  padding:9px 18px; background:linear-gradient(135deg,var(--gold),var(--gold2));
  color:#0a0600; border:none; border-radius:7px;
  font-size:13px; font-weight:700; cursor:pointer; white-space:nowrap;
  font-family:var(--font-ui);
}
.btn-add:hover { opacity:.9; }
.imsg { font-size:12px; margin-top:8px; min-height:16px; }
.imsg.ok  { color:var(--green2); }
.imsg.err { color:var(--red2); }

/* 403 */
.f403 { text-align:center; padding:80px 20px; }
.f403-code  { font-size:90px; font-weight:800; color:var(--red2); line-height:1; font-family:var(--font-display); }
.f403-title { font-size:22px; font-weight:700; margin:14px 0 10px; font-family:var(--font-display); }
.f403-desc  { font-size:13px; color:var(--muted); margin-bottom:28px; line-height:1.7; }
.btn-back { padding:11px 28px; background:linear-gradient(135deg,var(--gold),var(--gold2)); color:#0a0600; border:none; border-radius:8px; font-size:14px; font-weight:700; cursor:pointer; font-family:var(--font-ui); }

/* empty */
.empty { color:var(--faint); font-size:13px; padding:24px 20px; text-align:center; }

/* perm table */
.perm-icon { font-size:15px; text-align:center; }

/* toast */
#toasts { position:fixed; bottom:20px; right:20px; display:flex; flex-direction:column; gap:8px; z-index:999; }
.toast {
  background:var(--bg2); border:1px solid var(--border); border-radius:10px;
  padding:11px 16px; font-size:13px; display:flex; align-items:center; gap:10px;
  min-width:240px; box-shadow:0 12px 32px rgba(0,0,0,.5);
  animation:tin .25s ease;
}
@keyframes tin { from{opacity:0;transform:translateX(20px)} to{opacity:1} }
.toast.ok  { border-left:3px solid var(--green2); }
.toast.err { border-left:3px solid var(--red2); }

/* mono money */
.money { font-family:var(--font-mono); }

@media (max-width:600px) {
  .login-center { padding: 16px 12px; }
  .lcard { padding: 24px 20px 20px; border-radius:14px; }
}
</style>
</head>
<body>

<!-- ╔═══════════════════════════╗ -->
<!-- ║       LOGIN PAGE          ║ -->
<!-- ╚═══════════════════════════╝ -->
<div id="pgLogin" class="page on">
  <div class="login-center">

    <!-- Meridian Bank star logo -->
    <div class="ns-logo">
      <svg class="ns-star" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
        <polygon points="32,2 36,28 62,32 36,36 32,62 28,36 2,32 28,28"
                 fill="none" stroke="#4ea06e" stroke-width="1.5" stroke-linejoin="round"/>
        <polygon points="32,10 34.5,29.5 54,32 34.5,34.5 32,54 29.5,34.5 10,32 29.5,29.5"
                 fill="rgba(78,160,110,0.10)"/>
        <circle cx="32" cy="32" r="3" fill="#4ea06e" opacity="0.9"/>
        <polygon points="32,1 32.8,4.5 36,5.5 32.8,6.5 32,10 31.2,6.5 28,5.5 31.2,4.5"
                 fill="#6fcf97" opacity="0.7"/>
      </svg>
      <div class="ns-brand">
        <span class="word1">Meridian</span>
        <span class="word2">Bank</span>
      </div>
    </div>

    <div class="ns-title">Secure Access Portal</div>
    <div class="ns-subtitle">Let's get you signed in.</div>

    <div class="lcard">
      <div class="tabs">
        <div class="tab active" id="tL" onclick="swTab('l')">Sign In</div>
        <div class="tab"        id="tR" onclick="swTab('r')">New Account</div>
      </div>

      <!-- LOGIN PANEL -->
      <div class="tp active" id="pL">
        <div class="fg">
          <input id="lU" placeholder="Enter your username" autocomplete="off"
                 onkeydown="if(event.key==='Enter')doLogin()">
        </div>
        <div class="fg">
          <div class="input-wrap">
            <input id="lP" type="password" placeholder="Enter your password"
                   onkeydown="if(event.key==='Enter')doLogin()">
            <span class="pw-eye" id="pwEye" onclick="togglePw()">👁</span>
          </div>
        </div>

        <button class="btn-main" id="btnL" onclick="doLogin()">Login →</button>
        <div class="fm" id="lMsg"></div>

        <!-- Quick Access -->
        <div style="margin-top:22px;">
          <div style="text-align:center;font-size:10px;font-weight:700;letter-spacing:1.5px;color:var(--faint);margin-bottom:12px;text-transform:uppercase;">Quick Access Accounts</div>
          <div style="display:flex;flex-wrap:wrap;justify-content:center;gap:8px;">
            <button class="qb sa" onclick="fill('superadmin','super123')">Super Admin 🛡</button>
            <button class="qb au" onclick="fill('auditor1','audit123')">Network Analyst 🔍</button>
            <button class="qb tl" onclick="fill('teller1','teller123')">Branch Teller 💳</button>
            <button class="qb mg" onclick="fill('manager1','mgr123')">Branch Manager 🏛</button>
            <button class="qb cu" onclick="fill('alice','alice123')">Alice Fernandez 👤</button>
            <button class="qb cu" onclick="fill('bob','bob123')">Bob Krishnan 👤</button>
          </div>
        </div>

        <div class="ns-security-note">
          <span class="shield">🛡</span>
          <span>Your security is our priority. Meridian Bank will never ask for your PIN or password via email or SMS.</span>
        </div>
      </div>

      <!-- REGISTER PANEL -->
      <div class="tp" id="pR">
        <div class="fg">
          <input id="rN" placeholder="Your full name" autocomplete="off">
        </div>
        <div class="fg">
          <input id="rU" placeholder="Choose a username" autocomplete="off">
        </div>
        <div class="fg">
          <input id="rP" type="password" placeholder="Create a password">
        </div>
        <button class="btn-main" id="btnR" onclick="doRegister()">Open Account →</button>
        <div class="fm" id="rMsg"></div>
        <div style="margin-top:12px;font-size:11px;color:var(--faint);text-align:center;">
          New accounts are created as <strong style="color:var(--green2)">Customer</strong> role
        </div>
      </div>
    </div>

    <div style="margin-top:20px;font-size:10px;color:var(--faint);text-align:center;letter-spacing:.5px;">
      Data Diggers · NULL Student Chapter · VIT Bhopal
    </div>
  </div>
</div>
<!-- ╔═══════════════════════════╗ -->
<!-- ║        APP PAGE           ║ -->
<!-- ╚═══════════════════════════╝ -->
<div id="pgApp" class="page">

  <div class="topbar">
    <div class="tlogo">
      <div class="tlogo-icon" style="background:none;padding:0;width:30px;height:30px;">
        <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:30px;height:30px;filter:drop-shadow(0 0 6px rgba(78,160,110,0.5))">
          <polygon points="32,2 36,28 62,32 36,36 32,62 28,36 2,32 28,28"
                   fill="none" stroke="#4ea06e" stroke-width="2" stroke-linejoin="round"/>
          <polygon points="32,10 34.5,29.5 54,32 34.5,34.5 32,54 29.5,34.5 10,32 29.5,29.5"
                   fill="rgba(78,160,110,0.12)"/>
          <circle cx="32" cy="32" r="3.5" fill="#4ea06e"/>
          <polygon points="32,1 32.8,4.5 36,5.5 32.8,6.5 32,10 31.2,6.5 28,5.5 31.2,4.5"
                   fill="#6fcf97" opacity="0.8"/>
        </svg>
      </div>
      <div class="tlogo-name">Meridian Bank</div>
    </div>
    <div class="tright">
      <span class="tuser">Welcome, <strong id="topUser"></strong></span>
      <span class="rpill" id="topRole"></span>
      <button class="btn-out" onclick="doLogout()">Logout</button>
    </div>
  </div>

  <div class="app-body">
    <nav class="sidebar">
      <div class="slabel">General</div>
      <div class="sl active" id="sl-dashboard" onclick="go('dashboard')">
        <span class="sl-icon">📊</span> Dashboard
      </div>
      <div class="sl" id="sl-profile" onclick="go('profile')">
        <span class="sl-icon">👤</span> My Profile
      </div>
      <div class="sl" id="sl-account" onclick="go('account')">
        <span class="sl-icon">💰</span> My Account
      </div>
      <div class="sl" id="sl-transfer" onclick="go('transfer')">
        <span class="sl-icon">↔️</span> Transfer
      </div>

      <div class="slabel" style="margin-top:8px">Privileged</div>
      <div class="sl locked" id="sl-accounts">
        <span class="sl-icon">🏦</span> All Accounts 🔒
      </div>
      <div class="sl locked" id="sl-transactions">
        <span class="sl-icon">📋</span> Transactions 🔒
      </div>
      <div class="sl locked" id="sl-loans">
        <span class="sl-icon">💼</span> Loan Apps 🔒
      </div>
      <div class="sl locked" id="sl-users">
        <span class="sl-icon">⚙️</span> Manage Users 🔒
      </div>
      <div class="sl locked" id="sl-logs">
        <span class="sl-icon">🔍</span> Audit Logs 🔒
      </div>
    </nav>

    <main class="main">

      <!-- DASHBOARD -->
      <div class="view active" id="vDashboard">
        <div class="vtitle"><h2>Dashboard</h2> <small id="dashSub">Welcome to Meridian Bank</small></div>

        <div class="stats" id="statsGrid">
          <div class="sbox gold">
            <div class="sval gold money" id="stBal">—</div>
            <div class="slbl" id="stBalLabel">Total Deposits</div>
          </div>
          <div class="sbox blue">
            <div class="sval blue" id="stTx">—</div>
            <div class="slbl">Transactions</div>
          </div>
          <div class="sbox green">
            <div class="sval green" id="stU">—</div>
            <div class="slbl">Registered Users</div>
          </div>
          <div class="sbox red">
            <div class="sval red" id="stB">—</div>
            <div class="slbl">Security Alerts</div>
          </div>
        </div>

        <div class="card">
          <div class="chead">
            <span>Permission Matrix — Your Role Access</span>
            <span id="myRoleBadge"></span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Permission</th>
                <th>Super Admin</th>
                <th>Bank Manager</th>
                <th>Teller</th>
                <th>Auditor</th>
                <th>Customer</th>
                <th>You</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>View All Accounts</td>
                <td class="perm-icon">✅</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td>
                <td id="pm1" class="perm-icon">—</td>
              </tr>
              <tr>
                <td>Process Transactions</td>
                <td class="perm-icon">✅</td><td class="perm-icon">✅</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td><td class="perm-icon">✅</td>
                <td id="pm2" class="perm-icon">—</td>
              </tr>
              <tr>
                <td>Approve Loans</td>
                <td class="perm-icon">✅</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td>
                <td id="pm3" class="perm-icon">—</td>
              </tr>
              <tr>
                <td>View Audit Logs</td>
                <td class="perm-icon">✅</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td>
                <td id="pm4" class="perm-icon">—</td>
              </tr>
              <tr>
                <td>Manage Users</td>
                <td class="perm-icon">✅</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td>
                <td id="pm5" class="perm-icon">—</td>
              </tr>
              <tr>
                <td>Freeze Accounts</td>
                <td class="perm-icon">✅</td><td class="perm-icon">✅</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td>
                <td id="pm6" class="perm-icon">—</td>
              </tr>
              <tr>
                <td>System Config</td>
                <td class="perm-icon">✅</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td><td class="perm-icon">❌</td>
                <td id="pm7" class="perm-icon">—</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="chead">Recent Activity</div>
          <div id="recentLogs"><div class="empty">Loading...</div></div>
        </div>
      </div>

      <!-- PROFILE -->
      <div class="view" id="vProfile">
        <div class="vtitle"><h2>My Profile</h2></div>
        <div class="card"><div id="profileData"></div></div>
        <div class="card">
          <div class="chead">My Permissions</div>
          <div id="myPerms" class="cpad" style="display:flex;flex-wrap:wrap;gap:8px;"></div>
        </div>
      </div>

      <!-- MY ACCOUNT -->
      <div class="view" id="vAccount">
        <div class="vtitle"><h2>My Account</h2></div>
        <div class="card">
          <div class="balance-display">
            <div class="balance-label">Available Balance</div>
            <div class="balance-amount" id="myBalance">—</div>
            <div class="balance-acc" id="myAccNo">—</div>
          </div>
          <div id="myAccData"></div>
        </div>
        <div class="card">
          <div class="chead">Recent Transactions</div>
          <table>
            <thead><tr><th>TXN ID</th><th>From</th><th>To</th><th>Amount</th><th>Note</th><th>Status</th></tr></thead>
            <tbody id="myTxRows"><tr><td colspan="6" class="empty">No transactions yet.</td></tr></tbody>
          </table>
        </div>
      </div>

      <!-- TRANSFER -->
      <div class="view" id="vTransfer">
        <div class="vtitle"><h2>Fund Transfer</h2></div>
        <div class="card">
          <div class="chead">New Transfer</div>
          <div class="cpad">
            <div class="tx-form">
              <div class="fg">
                <label>From Account</label>
                <input id="txFrom" placeholder="e.g. HDFC005">
              </div>
              <div class="fg">
                <label>To Account</label>
                <input id="txTo" placeholder="e.g. HDFC006">
              </div>
              <div class="fg">
                <label>Amount (₹)</label>
                <input id="txAmt" type="number" placeholder="0.00">
              </div>
              <div class="fg">
                <label>Note</label>
                <input id="txNote" placeholder="Payment note...">
              </div>
              <div class="full">
                <button class="btn-transfer" onclick="doTransfer()">⚡ Process Transfer</button>
                <div class="imsg" id="txMsg"></div>
              </div>
            </div>
          </div>
        </div>
        <div class="card" id="txResultCard" style="display:none;">
          <div class="chead">Transfer Receipt</div>
          <div id="txResult" class="cpad"></div>
        </div>
      </div>

      <!-- ALL ACCOUNTS -->
      <div class="view" id="vAccounts">
        <div class="vtitle"><h2>All Accounts</h2> <small>Privileged view</small></div>
        <div class="card">
          <div class="chead">Account Registry</div>
          <table>
            <thead><tr><th>Account No</th><th>Full Name</th><th>Role</th><th>Balance</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody id="allAccRows"></tbody>
          </table>
        </div>
      </div>

      <!-- TRANSACTIONS -->
      <div class="view" id="vTransactions">
        <div class="vtitle"><h2>All Transactions</h2> <small>Reports access</small></div>
        <div class="card">
          <table>
            <thead><tr><th>TXN ID</th><th>From</th><th>To</th><th>Type</th><th>Amount</th><th>Note</th><th>Status</th><th>Time</th></tr></thead>
            <tbody id="allTxRows"></tbody>
          </table>
        </div>
      </div>

      <!-- LOANS -->
      <div class="view" id="vLoans">
        <div class="vtitle"><h2>Loan Applications</h2> <small>Manager / Super Admin only</small></div>
        <div class="card">
          <table>
            <thead><tr><th>Loan ID</th><th>Applicant</th><th>Type</th><th>Amount</th><th>Status</th><th>Date</th><th>Action</th></tr></thead>
            <tbody id="loanRows"></tbody>
          </table>
        </div>
      </div>

      <!-- MANAGE USERS -->
      <div class="view" id="vUsers">
        <div class="vtitle"><h2>Manage Users</h2> <small>Admin access</small></div>
        <div class="card">
          <div class="chead">All Users</div>
          <table>
            <thead><tr><th>Username</th><th>Full Name</th><th>Role</th><th>Email</th><th>Actions</th></tr></thead>
            <tbody id="userRows"></tbody>
          </table>
        </div>
        <div class="card">
          <div class="chead">Add New User</div>
          <div class="cpad">
            <div class="add-row">
              <input id="nuFN" placeholder="Full Name">
              <input id="nuN"  placeholder="Username">
              <input id="nuP"  type="password" placeholder="Password">
              <select id="nuR">
                <option value="customer">Customer</option>
                <option value="teller">Teller</option>
                <option value="auditor">Auditor</option>
                <option value="bank_manager">Bank Manager</option>
                <option value="super_admin">Super Admin</option>
              </select>
              <input id="nuBal" type="number" placeholder="Initial Balance" value="10000">
              <button class="btn-add" onclick="addUser()">Add User</button>
            </div>
            <div class="imsg" id="addMsg"></div>
          </div>
        </div>
      </div>

      <!-- AUDIT LOGS -->
      <div class="view" id="vLogs">
        <div class="vtitle"><h2>Audit Logs</h2> <small>Security trail</small></div>
        <div class="card"><div id="allLogs"><div class="empty">Loading...</div></div></div>
      </div>

      <!-- 403 -->
      <div class="view" id="vForbidden">
        <div class="f403">
          <div class="f403-code">403</div>
          <div class="f403-title">Access Denied</div>
          <p class="f403-desc">Your role (<b id="forbidRole" style="color:var(--red2)"></b>) does not have permission to access this area.<br>This unauthorized access attempt has been logged.</p>
          <button class="btn-back" onclick="go('dashboard')">← Return to Dashboard</button>
        </div>
      </div>

    </main>
  </div>
</div>

<div id="toasts"></div>

<script>
// ── STATE ──────────────────────────────────────────────
var TOKEN = null;
var ME    = null;
var MY_PERMS = [];
var blockedCount = 0;

// Permission gates for each view
var VIEW_PERMS = {
  accounts:     "view_all",
  transactions: "view_reports",
  loans:        "approve_loans",
  users:        "manage_users",
  logs:         "view_audit",
};

// ── HELPERS ────────────────────────────────────────────
function showPage(id) {
  document.querySelectorAll(".page").forEach(function(p){ p.classList.remove("on"); });
  document.getElementById(id).classList.add("on");
}

function swTab(t) {
  ["tL","tR"].forEach(function(id){
    document.getElementById(id).classList.toggle("active", (id==="tL")===(t==="l"));
  });
  ["pL","pR"].forEach(function(id){
    document.getElementById(id).classList.toggle("active", (id==="pL")===(t==="l"));
  });
}

function fill(u, p) {
  document.getElementById("lU").value = u;
  document.getElementById("lP").value = p;
}

function togglePw() {
  var inp = document.getElementById("lP");
  var eye = document.getElementById("pwEye");
  if (inp.type === "password") { inp.type = "text"; eye.textContent = "🙈"; }
  else { inp.type = "password"; eye.textContent = "👁"; }
}

function hasPerm(perm) {
  return MY_PERMS.indexOf(perm) !== -1;
}

function fmt(n) {
  return "₹" + Number(n).toLocaleString("en-IN", {minimumFractionDigits:2, maximumFractionDigits:2});
}

// ── API ────────────────────────────────────────────────
async function api(method, path, body) {
  var opts = { method:method, headers:{"Content-Type":"application/json"} };
  if (TOKEN) opts.headers["Authorization"] = "Bearer " + TOKEN;
  if (body)  opts.body = JSON.stringify(body);
  try {
    var res  = await fetch(path, opts);
    var data = await res.json();
    return { ok:res.ok, status:res.status, data:data };
  } catch(e) {
    return { ok:false, data:{error:"Cannot reach server. Is Flask running?"} };
  }
}

// ── AUTH ───────────────────────────────────────────────
async function doLogin() {
  var un  = document.getElementById("lU").value.trim().toLowerCase();
  var pw  = document.getElementById("lP").value;
  var msg = document.getElementById("lMsg");
  var btn = document.getElementById("btnL");

  msg.className = "fm"; msg.textContent = "";
  if (!un || !pw) { msg.className="fm err"; msg.textContent="Enter username and password."; return; }

  btn.textContent = "Authenticating..."; btn.disabled = true;
  var r = await api("POST", "/api/login", {username:un, password:pw});

  if (!r.ok) {
    msg.className="fm err"; msg.textContent="❌ "+r.data.error;
    btn.textContent="Login →"; btn.disabled=false; return;
  }

  TOKEN = r.data.token;
  ME    = r.data;
  btn.textContent="Login →"; btn.disabled=false;

  // fetch full profile for permissions
  var pr = await api("GET", "/api/me");
  if (pr.ok) MY_PERMS = pr.data.permissions || [];

  launchApp();
}

async function doRegister() {
  var fn  = document.getElementById("rN").value.trim();
  var un  = document.getElementById("rU").value.trim().toLowerCase();
  var pw  = document.getElementById("rP").value;
  var msg = document.getElementById("rMsg");
  var btn = document.getElementById("btnR");

  msg.className="fm"; msg.textContent="";
  if (!un || !pw) { msg.className="fm err"; msg.textContent="Please fill in all fields."; return; }

  btn.textContent="Opening account..."; btn.disabled=true;
  var r = await api("POST", "/api/register", {username:un, password:pw, fullname:fn});

  if (!r.ok) {
    msg.className="fm err"; msg.textContent="❌ "+r.data.error;
    btn.textContent="Open Account →"; btn.disabled=false; return;
  }

  msg.className="fm ok"; msg.textContent="✅ Account created! Logging in...";
  var lr = await api("POST", "/api/login", {username:un, password:pw});
  TOKEN  = lr.data.token;
  ME     = lr.data;
  MY_PERMS = ["view_own", "process_tx"];

  setTimeout(function(){
    btn.textContent="Open Account →"; btn.disabled=false;
    msg.textContent="";
    launchApp();
  }, 700);
}

function doLogout() {
  TOKEN=null; ME=null; MY_PERMS=[]; blockedCount=0;
  document.getElementById("lU").value="";
  document.getElementById("lP").value="";
  document.getElementById("lMsg").textContent="";
  showPage("pgLogin"); swTab("l");
}

// ── LAUNCH ─────────────────────────────────────────────
function launchApp() {
  document.getElementById("topUser").textContent = ME.fullname || ME.username;
  var rp = document.getElementById("topRole");
  rp.textContent  = ME.role.replace("_"," ").toUpperCase();
  rp.className    = "rpill " + ME.role;

  // unlock sidebar
  var unlocks = {
    accounts:     "view_all",
    transactions: "view_reports",
    loans:        "approve_loans",
    users:        "manage_users",
    logs:         "view_audit",
  };

  for (var view in unlocks) {
    var sl = document.getElementById("sl-" + view);
    var perm = unlocks[view];
    if (hasPerm(perm)) {
      sl.classList.remove("locked");
      sl.innerHTML = sl.innerHTML.replace(" 🔒","");
      (function(v){ sl.onclick = function(){ go(v); }; })(view);
    }
  }

  // permission matrix - "You" column
  var permMap = {
    pm1: "view_all",
    pm2: "process_tx",
    pm3: "approve_loans",
    pm4: "view_audit",
    pm5: "manage_users",
    pm6: "freeze_accounts",
    pm7: "system_config",
  };
  for (var id in permMap) {
    document.getElementById(id).innerHTML = hasPerm(permMap[id]) ? "✅" : "❌";
  }

  document.getElementById("myRoleBadge").innerHTML =
    "<span class='badge "+ME.role+"'>"+ME.role.replace("_"," ").toUpperCase()+"</span>";

  // pre-fill transfer from field
  if (ME.account_no) {
    document.getElementById("txFrom").value = ME.account_no;
  }

  showPage("pgApp");
  go("dashboard");
}

// ── ROUTING ────────────────────────────────────────────
function go(view) {
  var requiredPerm = VIEW_PERMS[view];
  if (requiredPerm && !hasPerm(requiredPerm)) {
    blockedCount++;
    document.getElementById("stB").textContent = blockedCount;
    document.getElementById("forbidRole").textContent = ME.role.replace("_"," ").toUpperCase();
    toast("403 — Permission denied. Access logged.", "err");
    showView("vForbidden");
    return;
  }

  document.querySelectorAll(".sl:not(.locked)").forEach(function(s){ s.classList.remove("active"); });
  var sl = document.getElementById("sl-"+view);
  if (sl) sl.classList.add("active");

  var map = {
    dashboard:"vDashboard", profile:"vProfile", account:"vAccount",
    transfer:"vTransfer", accounts:"vAccounts", transactions:"vTransactions",
    loans:"vLoans", users:"vUsers", logs:"vLogs"
  };
  showView(map[view] || "vDashboard");

  var loaders = {
    dashboard:    loadDashboard,
    profile:      loadProfile,
    account:      loadAccount,
    accounts:     loadAccounts,
    transactions: loadTransactions,
    loans:        loadLoans,
    users:        loadUsers,
    logs:         loadLogs,
  };
  if (loaders[view]) loaders[view]();
}

function showView(id) {
  document.querySelectorAll(".view").forEach(function(v){ v.classList.remove("active"); });
  var el = document.getElementById(id);
  if (el) el.classList.add("active");
}

// ── DATA LOADERS ───────────────────────────────────────
async function loadDashboard() {
  var r = await api("GET", "/api/stats");
  if (!r.ok) return;
  var d = r.data;
  document.getElementById("stBal").textContent = fmt(d.total_balance);
  document.getElementById("stTx").textContent  = d.total_transactions;
  document.getElementById("stU").textContent   = d.total_users;
  document.getElementById("stB").textContent   = d.blocked + blockedCount;

  if (d.role === "customer") {
    document.getElementById("stBalLabel").textContent = "My Balance";
  }

  var el = document.getElementById("recentLogs");
  el.innerHTML = d.recent && d.recent.length
    ? d.recent.map(logHTML).join("")
    : '<div class="empty">No recent activity.</div>';
}

async function loadProfile() {
  var r = await api("GET", "/api/me");
  if (!r.ok) return;
  var d = r.data;
  document.getElementById("profileData").innerHTML =
    pr("Full Name",    d.fullname) +
    pr("Username",     d.username) +
    pr("Email",        d.email) +
    pr("Account No",   "<span style='font-family:var(--font-mono);color:var(--gold2)'>"+d.account_no+"</span>") +
    pr("Role",         "<span class='badge "+d.role+"'>"+d.role.replace("_"," ").toUpperCase()+"</span>") +
    pr("Account Status", "<span class='badge "+(d.status||"active")+"'>"+((d.status||"active").toUpperCase())+"</span>") +
    pr("Member Since", d.joined || "—") +
    pr("Session",      "Active · expires in 4 hours");

  var permsEl = document.getElementById("myPerms");
  permsEl.innerHTML = (d.permissions || []).map(function(p){
    return "<span class='role-chip customer' style='font-size:11px'>✓ "+p.replace("_"," ")+"</span>";
  }).join("");
}

async function loadAccount() {
  var r = await api("GET", "/api/my-account");
  if (!r.ok) return;
  var d = r.data;
  document.getElementById("myBalance").textContent = fmt(d.balance);
  document.getElementById("myAccNo").textContent   = "Account: " + d.account_no + " · " + (d.status||"active").toUpperCase();

  document.getElementById("myAccData").innerHTML =
    pr("Account Holder", ME.fullname) +
    pr("Account Number", "<span style='font-family:var(--font-mono);color:var(--gold2)'>"+d.account_no+"</span>") +
    pr("Account Type",   "Savings Account") +
    pr("Status",         "<span class='badge "+(d.status||"active")+"'>"+((d.status||"active").toUpperCase())+"</span>");

  document.getElementById("myTxRows").innerHTML = d.transactions && d.transactions.length
    ? d.transactions.map(function(t){
        return "<tr><td><span style='font-family:var(--font-mono);font-size:11px;color:var(--gold2)'>"+t.id+"</span></td>" +
          "<td>"+t.from+"</td><td>"+t.to+"</td>" +
          "<td class='money' style='color:var(--green2)'>"+fmt(t.amount)+"</td>" +
          "<td>"+t.note+"</td>" +
          "<td><span class='badge "+t.status+"'>"+t.status+"</span></td></tr>";
      }).join("")
    : "<tr><td colspan='6' class='empty'>No transactions found.</td></tr>";
}

async function doTransfer() {
  var frm  = document.getElementById("txFrom").value.trim().toUpperCase();
  var to   = document.getElementById("txTo").value.trim().toUpperCase();
  var amt  = parseFloat(document.getElementById("txAmt").value) || 0;
  var note = document.getElementById("txNote").value.trim() || "Transfer";
  var msg  = document.getElementById("txMsg");

  if (!frm || !to || !amt) {
    msg.className="imsg err"; msg.textContent="Please fill all fields."; return;
  }

  var r = await api("POST", "/api/transfer", {from_account:frm, to_account:to, amount:amt, note:note});
  msg.className = "imsg " + (r.ok ? "ok" : "err");
  msg.textContent = r.ok ? "✅ Transfer successful!" : "❌ "+r.data.error;

  if (r.ok) {
    var t = r.data.transaction;
    var card = document.getElementById("txResultCard");
    card.style.display = "block";
    document.getElementById("txResult").innerHTML =
      pr("Transaction ID", "<span style='font-family:var(--font-mono);color:var(--gold2)'>"+t.id+"</span>") +
      pr("From Account",   t.from) +
      pr("To Account",     t.to) +
      pr("Amount",         "<span style='color:var(--green2);font-family:var(--font-mono)'>"+fmt(t.amount)+"</span>") +
      pr("Note",           t.note) +
      pr("Status",         "<span class='badge completed'>COMPLETED</span>") +
      pr("Timestamp",      t.time);
    toast("Transfer of "+fmt(amt)+" successful!", "ok");
    document.getElementById("txAmt").value="";
    document.getElementById("txNote").value="";
  }
}

async function loadAccounts() {
  var r = await api("GET", "/api/accounts");
  if (!r.ok) return;
  document.getElementById("allAccRows").innerHTML = r.data.accounts.map(function(a){
    var actions = "";
    if (hasPerm("freeze_accounts")) {
      var isFrozen = a.status === "frozen";
      actions += "<button class='act "+(isFrozen?"g":"y")+"' onclick='toggleFreeze(\""+a.username+"\",\""+(isFrozen?"unfreeze":"freeze")+"\")'>"+
        (isFrozen ? "✅ Unfreeze" : "🔒 Freeze")+"</button>&nbsp;";
    }
    return "<tr>" +
      "<td><span style='font-family:var(--font-mono);color:var(--gold2)'>"+a.account_no+"</span></td>" +
      "<td>"+a.fullname+"</td>" +
      "<td><span class='badge "+a.role+"'>"+a.role.replace("_"," ").toUpperCase()+"</span></td>" +
      "<td class='money' style='color:var(--green2)'>"+fmt(a.balance)+"</td>" +
      "<td><span class='badge "+(a.status||"active")+"'>"+((a.status||"active").toUpperCase())+"</span></td>" +
      "<td>"+actions+"</td></tr>";
  }).join("");
}

async function toggleFreeze(username, action) {
  if (!confirm(action.charAt(0).toUpperCase()+action.slice(1)+" account of '"+username+"'?")) return;
  var r = await api("POST", "/api/freeze-account", {username:username, action:action});
  toast(r.ok ? r.data.message : r.data.error, r.ok?"ok":"err");
  if (r.ok) loadAccounts();
}

async function loadTransactions() {
  var r = await api("GET", "/api/transactions");
  if (!r.ok) return;
  document.getElementById("allTxRows").innerHTML = r.data.transactions.map(function(t){
    return "<tr>" +
      "<td><span style='font-family:var(--font-mono);font-size:11px;color:var(--gold2)'>"+t.id+"</span></td>" +
      "<td>"+t.from+"</td><td>"+t.to+"</td>" +
      "<td>"+t.type+"</td>" +
      "<td class='money' style='color:var(--green2)'>"+fmt(t.amount)+"</td>" +
      "<td style='color:var(--muted)'>"+t.note+"</td>" +
      "<td><span class='badge "+t.status+"'>"+t.status+"</span></td>" +
      "<td style='font-size:11px;color:var(--faint);font-family:var(--font-mono)'>"+t.time+"</td></tr>";
  }).join("");
}

async function loadLoans() {
  var r = await api("GET", "/api/loan-applications");
  if (!r.ok) return;
  document.getElementById("loanRows").innerHTML = r.data.loans.map(function(l){
    var actions = l.status === "pending"
      ? "<button class='act g' onclick='approveLoan(\""+l.id+"\",\"approve\")'>✅ Approve</button>&nbsp;" +
        "<button class='act r' onclick='approveLoan(\""+l.id+"\",\"reject\")'>❌ Reject</button>"
      : "<span style='color:var(--faint);font-size:12px'>Processed</span>";
    return "<tr>" +
      "<td><span style='font-family:var(--font-mono);color:var(--gold2)'>"+l.id+"</span></td>" +
      "<td>"+l.applicant+"</td>" +
      "<td>"+l.type+"</td>" +
      "<td class='money' style='color:var(--green2)'>"+fmt(l.amount)+"</td>" +
      "<td><span class='badge "+l.status+"'>"+l.status+"</span></td>" +
      "<td style='font-size:12px;color:var(--muted)'>"+l.date+"</td>" +
      "<td>"+actions+"</td></tr>";
  }).join("");
}

async function approveLoan(id, action) {
  var r = await api("POST", "/api/approve-loan", {loan_id:id, action:action});
  toast(r.ok ? r.data.message : r.data.error, r.ok?"ok":"err");
  if (r.ok) loadLoans();
}

async function loadUsers() {
  var r = await api("GET", "/api/accounts");
  if (!r.ok) return;
  var isSA = ME.role === "super_admin";
  document.getElementById("userRows").innerHTML = r.data.accounts.map(function(u){
    var actions = "";
    if (isSA) {
      actions = "<div style='display:flex;gap:6px'>" +
        "<button class='act p' onclick='changeRole(\""+u.username+"\")'>Change Role</button>" +
        "<button class='act r' onclick='deleteUser(\""+u.username+"\")'>Delete</button>" +
        "</div>";
    }
    return "<tr>" +
      "<td>"+u.username+"</td>" +
      "<td>"+u.fullname+"</td>" +
      "<td><span class='badge "+u.role+"'>"+u.role.replace("_"," ").toUpperCase()+"</span></td>" +
      "<td style='font-size:12px;color:var(--muted)'>"+u.email+"</td>" +
      "<td>"+actions+"</td></tr>";
  }).join("");
}

async function addUser() {
  var fn  = document.getElementById("nuFN").value.trim();
  var un  = document.getElementById("nuN").value.trim().toLowerCase();
  var pw  = document.getElementById("nuP").value;
  var rol = document.getElementById("nuR").value;
  var bal = parseFloat(document.getElementById("nuBal").value) || 10000;
  var msg = document.getElementById("addMsg");

  if (!un || !pw) { msg.className="imsg err"; msg.textContent="Fill username and password."; return; }

  var r = await api("POST", "/api/admin/add-user", {username:un, password:pw, role:rol, fullname:fn, initial_balance:bal});
  msg.className = "imsg "+(r.ok?"ok":"err");
  msg.textContent = r.ok ? "✅ "+r.data.message : "❌ "+r.data.error;
  if (r.ok) { toast("User added","ok"); loadUsers(); document.getElementById("nuN").value=""; document.getElementById("nuP").value=""; document.getElementById("nuFN").value=""; }
}

async function deleteUser(username) {
  if (!confirm("Delete user '"+username+"'? This cannot be undone.")) return;
  var r = await api("POST", "/api/admin/delete-user", {username:username});
  toast(r.ok?r.data.message:r.data.error, r.ok?"ok":"err");
  if (r.ok) loadUsers();
}

async function changeRole(username) {
  var newRole = prompt("New role for '"+username+"':\nOptions: super_admin, bank_manager, teller, auditor, customer");
  if (!newRole) return;
  newRole = newRole.trim().toLowerCase();
  var r = await api("POST", "/api/admin/change-role", {username:username, role:newRole});
  toast(r.ok?r.data.message:r.data.error, r.ok?"ok":"err");
  if (r.ok) loadUsers();
}

async function loadLogs() {
  var r = await api("GET", "/api/audit-logs");
  if (!r.ok) return;
  var el = document.getElementById("allLogs");
  el.innerHTML = r.data.logs && r.data.logs.length
    ? r.data.logs.map(logHTML).join("")
    : '<div class="empty">No audit logs yet.</div>';
}

// ── RENDER HELPERS ─────────────────────────────────────
function logHTML(l) {
  return "<div class='li'>" +
    "<div class='ld "+l.kind+"'></div>" +
    "<span class='lt'>"+l.time+"</span>" +
    "<span class='lm "+l.kind+"'>"+l.msg+"</span></div>";
}

function pr(key, val) {
  return "<div class='pr'><span class='pk'>"+key+"</span><span class='pv'>"+val+"</span></div>";
}

function toast(msg, type) {
  var t = document.createElement("div");
  t.className = "toast "+(type||"ok");
  t.innerHTML = (type==="err" ? "❌ " : "✅ ")+msg;
  document.getElementById("toasts").appendChild(t);
  setTimeout(function(){ t.remove(); }, 3500);
}
</script>
</body>
</html>"""


@app.get("/")
def index():
    return render_template_string(HTML)


if __name__ == "__main__":
    print("\n  ✅  VaultSecure Banking RBAC")
    print("  → Open: http://localhost:5000\n")
    print("  ── Banking Roles & Credentials ──────────────────")
    print("  superadmin / super123      [Super Admin]")
    print("  manager1   / mgr123        [Bank Manager]")
    print("  teller1    / teller123     [Teller]")
    print("  auditor1   / audit123      [Auditor]")
    print("  alice      / alice123      [Customer]")
    print("  bob        / bob123        [Customer]")
    print("  carol      / carol123      [Customer]")
    print("  ─────────────────────────────────────────────────\n")
    app.run(debug=True, port=5000)