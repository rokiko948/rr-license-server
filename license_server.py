"""
╔══════════════════════════════════════════════════════════════╗
║  RR LICENSE SERVER  —  Run on your VPS                       ║
║  pip install flask                                          ║
║  python license_server.py                                   ║
╚══════════════════════════════════════════════════════════════╝

Endpoints:
  POST /api/activate   — Activate a license key (ties to machine)
  POST /api/check      — Validate license (kill switch check)
  POST /api/heartbeat  — Periodic ping from clients
  POST /api/log        — Receive usage logs from clients
  GET  /api/licenses   — List all licenses (your dashboard)
  GET  /api/logs       — View all logs
  POST /api/revoke     — Revoke a license
  POST /api/create     — Create a new license key

Storage: license_server_data.json (single file, simple)
"""

import os
import json
import uuid
import string
import random
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

DATA_FILE = os.path.join(os.environ.get("RENDER_DISK_PATH", os.path.dirname(os.path.abspath(__file__))), "license_server_data.json")
ADMIN_TOKEN = os.environ.get("RR_ADMIN_TOKEN", "changeme123")  # Set this in Render dashboard!

# ── DATA LAYER ────────────────────────────────────────────────────────────────

def load_data() -> dict:
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"licenses": {}, "logs": [], "admin_tokens": [ADMIN_TOKEN]}

def save_data(data: dict):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def generate_key() -> str:
    """Generate a license key like RRAT-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(random.choices(chars, k=4)) for _ in range(3)]
    return f"RRAT-{'-'.join(parts)}"

def require_admin(f):
    """Decorator: require admin token in Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        data = load_data()
        if token not in data.get("admin_tokens", []):
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── CLIENT ENDPOINTS ──────────────────────────────────────────────────────────

@app.route("/api/activate", methods=["POST"])
def activate():
    """Activate a license key — ties it to the client's machine fingerprint."""
    body = request.json or {}
    key = body.get("license_key", "").upper()
    fingerprint = body.get("fingerprint", "")
    system_info = body.get("system_info", {})

    if not key or not fingerprint:
        return jsonify({"ok": False, "error": "Missing license_key or fingerprint"})

    data = load_data()
    lic = data["licenses"].get(key)

    if not lic:
        return jsonify({"ok": False, "error": "Invalid license key"})

    if lic.get("revoked"):
        return jsonify({"ok": False, "error": "License has been revoked"})

    if lic.get("fingerprint") and lic["fingerprint"] != fingerprint:
        return jsonify({"ok": False, "error": "License already activated on another machine"})

    # Activate
    lic["fingerprint"] = fingerprint
    lic["activated_at"] = lic.get("activated_at") or datetime.now().isoformat()
    lic["last_check"] = datetime.now().isoformat()
    lic["system_info"] = system_info
    lic["activations"] = lic.get("activations", 0) + 1
    data["licenses"][key] = lic
    save_data(data)

    return jsonify({
        "ok": True,
        "message": "License activated",
        "plan": lic.get("plan", "standard"),
        "user": lic.get("user", {}),
    })

@app.route("/api/check", methods=["POST"])
def check():
    """Validate a license — this is the kill switch."""
    body = request.json or {}
    key = body.get("license_key", "").upper()
    fingerprint = body.get("fingerprint", "")

    if not key:
        return jsonify({"ok": False, "error": "Missing license_key"})

    data = load_data()
    lic = data["licenses"].get(key)

    if not lic:
        return jsonify({"ok": False, "error": "License not found"})

    if lic.get("revoked"):
        return jsonify({"ok": False, "error": "License has been revoked"})

    if lic.get("fingerprint") and lic["fingerprint"] != fingerprint:
        return jsonify({"ok": False, "error": "Fingerprint mismatch"})

    # Update last check
    lic["last_check"] = datetime.now().isoformat()
    data["licenses"][key] = lic
    save_data(data)

    return jsonify({
        "ok": True,
        "message": "License valid",
        "plan": lic.get("plan", "standard"),
    })

@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    """Receive heartbeat ping from clients."""
    body = request.json or {}
    key = body.get("license_key", "").upper()
    if not key:
        return jsonify({"ok": False})

    data = load_data()
    lic = data["licenses"].get(key)
    if lic and not lic.get("revoked"):
        lic["last_heartbeat"] = body.get("timestamp", datetime.now().isoformat())
        lic["heartbeat_count"] = lic.get("heartbeat_count", 0) + 1
        data["licenses"][key] = lic
        save_data(data)

    return jsonify({"ok": True})

@app.route("/api/log", methods=["POST"])
def receive_log():
    """Receive usage log from clients."""
    body = request.json or {}
    key = body.get("license_key", "").upper()
    if not key:
        return jsonify({"ok": False})

    data = load_data()
    log_entry = {
        "license_key": key,
        "fingerprint": body.get("fingerprint", ""),
        "event": body.get("event", "unknown"),
        "details": body.get("details", {}),
        "timestamp": body.get("timestamp", datetime.now().isoformat()),
        "received_at": datetime.now().isoformat(),
    }
    data["logs"].append(log_entry)
    # Keep last 10000 logs
    data["logs"] = data["logs"][-10000:]
    save_data(data)

    return jsonify({"ok": True})


# ── ADMIN ENDPOINTS (YOUR DASHBOARD) ─────────────────────────────────────────

@app.route("/api/licenses", methods=["GET"])
@require_admin
def list_licenses():
    """List all licenses with status."""
    data = load_data()
    result = []
    for key, lic in data["licenses"].items():
        result.append({
            "key": key,
            "plan": lic.get("plan", "standard"),
            "user": lic.get("user", {}),
            "revoked": lic.get("revoked", False),
            "fingerprint": lic.get("fingerprint", "not activated"),
            "activated_at": lic.get("activated_at"),
            "last_check": lic.get("last_check"),
            "last_heartbeat": lic.get("last_heartbeat"),
            "activations": lic.get("activations", 0),
            "system_info": lic.get("system_info", {}),
        })
    return jsonify({"ok": True, "licenses": result})

@app.route("/api/logs", methods=["GET"])
@require_admin
def list_logs():
    """View all usage logs."""
    data = load_data()
    key_filter = request.args.get("key")
    limit = int(request.args.get("limit", 100))
    logs = data["logs"]
    if key_filter:
        logs = [l for l in logs if l["license_key"] == key_filter.upper()]
    return jsonify({"ok": True, "logs": logs[-limit:]})

@app.route("/api/create", methods=["POST"])
@require_admin
def create_license():
    """Create a new license key."""
    body = request.json or {}
    key = generate_key()
    plan = body.get("plan", "standard")
    user = body.get("user", {})

    data = load_data()
    data["licenses"][key] = {
        "plan": plan,
        "user": user,
        "created_at": datetime.now().isoformat(),
        "revoked": False,
    }
    save_data(data)

    return jsonify({"ok": True, "license_key": key, "plan": plan, "user": user})

@app.route("/api/revoke", methods=["POST"])
@require_admin
def revoke_license():
    """Revoke a license — kill switch."""
    body = request.json or {}
    key = body.get("license_key", "").upper()

    data = load_data()
    if key not in data["licenses"]:
        return jsonify({"ok": False, "error": "License not found"})

    data["licenses"][key]["revoked"] = True
    data["licenses"][key]["revoked_at"] = datetime.now().isoformat()
    save_data(data)

    return jsonify({"ok": True, "message": f"License {key} revoked"})

@app.route("/api/unrevoke", methods=["POST"])
@require_admin
def unrevoke_license():
    """Re-enable a revoked license."""
    body = request.json or {}
    key = body.get("license_key", "").upper()

    data = load_data()
    if key not in data["licenses"]:
        return jsonify({"ok": False, "error": "License not found"})

    data["licenses"][key]["revoked"] = False
    data["licenses"][key].pop("revoked_at", None)
    save_data(data)

    return jsonify({"ok": True, "message": f"License {key} re-enabled"})


# ── WEB DASHBOARD ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Web dashboard for license management."""
    html = '''<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RR License Manager</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.header{background:#1e293b;padding:20px;border-bottom:1px solid #334155;display:flex;align-items:center;gap:15px}
.header h1{font-size:1.4em;color:#f8fafc}
.header span{color:#94a3b8;font-size:.9em}
.container{max-width:1200px;margin:0 auto;padding:20px}
.auth-box{background:#1e293b;border-radius:12px;padding:30px;text-align:center;max-width:400px;margin:60px auto}
.auth-box h2{margin-bottom:15px;color:#f8fafc}
.auth-box input{font-size:16px;padding:12px;width:100%;border:2px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;margin-bottom:12px}
.auth-box button{padding:12px 30px;font-size:16px;background:#3b82f6;color:white;border:none;border-radius:8px;cursor:pointer;width:100%}
.auth-box button:hover{background:#2563eb}
.auth-box .error{color:#ef4444;margin-top:10px}
.tabs{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.tab{padding:10px 20px;background:#1e293b;border:1px solid #334155;border-radius:8px;cursor:pointer;color:#94a3b8;font-size:.95em}
.tab.active{background:#3b82f6;color:white;border-color:#3b82f6}
.panel{display:none}.panel.active{display:block}
.card{background:#1e293b;border-radius:12px;padding:20px;margin-bottom:15px;border:1px solid #334155}
.card h3{color:#f8fafc;margin-bottom:10px}
input,select{font-size:14px;padding:10px;border:1px solid #334155;border-radius:6px;background:#0f172a;color:#e2e8f0;width:100%;margin-bottom:10px}
button{padding:10px 20px;background:#3b82f6;color:white;border:none;border-radius:6px;cursor:pointer;font-size:14px}
button:hover{background:#2563eb}
button.danger{background:#ef4444}.button.danger:hover{background:#dc2626}
button.success{background:#22c55e}.button.success:hover{background:#16a34a}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #334155;font-size:.9em}
th{color:#94a3b8;font-weight:600}
.badge{padding:3px 8px;border-radius:4px;font-size:.8em;font-weight:600}
.badge.active{background:#064e3b;color:#34d399}
.badge.revoked{background:#450a0a;color:#f87171}
.actions{display:flex;gap:6px}
.status{padding:12px;border-radius:8px;margin:10px 0;display:none}
.status.show{display:block}
.status.ok{background:#064e3b;color:#34d399}
.status.err{background:#450a0a;color:#f87171}
.log-entry{background:#0f172a;padding:10px;border-radius:6px;margin-bottom:8px;font-size:.85em}
.log-entry .time{color:#64748b}.log-entry .event{color:#3b82f6;font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:#1e293b;padding:15px;border-radius:10px;text-align:center;border:1px solid #334155}
.stat .num{font-size:1.8em;font-weight:700;color:#3b82f6}.stat .label{color:#94a3b8;font-size:.85em}
</style></head><body>

<div id="authSection">
  <div class="auth-box">
    <h2>🔐 RR License Manager</h2>
    <input type="password" id="tokenInput" placeholder="Enter admin token" autofocus>
    <button onclick="login()">Login</button>
    <div class="error" id="authError"></div>
  </div>
</div>

<div id="mainApp" style="display:none">
  <div class="header">
    <h1>🔑 RR License Manager</h1>
    <span id="statusText"></span>
  </div>
  <div class="container">
    <div class="stats" id="statsBar"></div>
    <div class="tabs">
      <div class="tab active" onclick="showTab('licenses')">📋 Licenses</div>
      <div class="tab" onclick="showTab('create')">➕ Create</div>
      <div class="tab" onclick="showTab('logs')">📊 Logs</div>
    </div>
    <div class="status" id="statusMsg"></div>
    
    <div id="licenses" class="panel active">
      <div id="licenseList">Loading...</div>
    </div>
    
    <div id="create" class="panel">
      <div class="card">
        <h3>Create New License</h3>
        <input id="newName" placeholder="Customer name">
        <input id="newEmail" placeholder="Customer email (optional)">
        <select id="newPlan">
          <option value="standard">Standard</option>
          <option value="pro">Pro</option>
          <option value="enterprise">Enterprise</option>
        </select>
        <button onclick="createLicense()">Create License Key</button>
        <div class="status" id="createResult"></div>
      </div>
    </div>
    
    <div id="logs" class="panel">
      <div class="card">
        <h3>Usage Logs</h3>
        <input id="logFilter" placeholder="Filter by license key (optional)">
        <button onclick="loadLogs()">Refresh</button>
      </div>
      <div id="logList">Loading...</div>
    </div>
  </div>
</div>

<script>
let TOKEN = '';

function api(endpoint, method='GET', body=null) {
  const opts = {method, headers:{'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'}};
  if(body) opts.body = JSON.stringify(body);
  return fetch('/api/'+endpoint, opts).then(r=>r.json());
}

function show(el, msg, type='ok') {
  el.className = 'status show ' + type;
  el.textContent = msg;
  setTimeout(()=>el.className='status', 4000);
}

async function login() {
  TOKEN = document.getElementById('tokenInput').value;
  try {
    const r = await api('licenses');
    if(r.ok) {
      document.getElementById('authSection').style.display='none';
      document.getElementById('mainApp').style.display='block';
      loadAll();
    } else {
      document.getElementById('authError').textContent = 'Invalid token';
    }
  } catch(e) {
    document.getElementById('authError').textContent = 'Connection error';
  }
}

document.getElementById('tokenInput').addEventListener('keydown', e => { if(e.key==='Enter') login(); });

function showTab(name) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(name).classList.add('active');
  event.target.classList.add('active');
  if(name==='licenses') loadLicenses();
  if(name==='logs') loadLogs();
}

async function loadAll() {
  const r = await api('licenses');
  if(!r.ok) return;
  const licenses = r.licenses || [];
  const active = licenses.filter(l=>!l.revoked).length;
  const revoked = licenses.filter(l=>l.revoked).length;
  document.getElementById('statsBar').innerHTML = 
    `<div class="stat"><div class="num">${licenses.length}</div><div class="label">Total Licenses</div></div>` +
    `<div class="stat"><div class="num">${active}</div><div class="label">Active</div></div>` +
    `<div class="stat"><div class="num">${revoked}</div><div class="label">Revoked</div></div>`;
  document.getElementById('statusText').textContent = `Server connected • ${licenses.length} licenses`;
  renderLicenses(licenses);
}

async function loadLicenses() {
  const r = await api('licenses');
  if(r.ok) renderLicenses(r.licenses||[]);
}

function renderLicenses(licenses) {
  if(!licenses.length) {
    document.getElementById('licenseList').innerHTML = '<div class="card"><p style="color:#64748b">No licenses yet. Create one!</p></div>';
    return;
  }
  let html = '<table><tr><th>Key</th><th>User</th><th>Plan</th><th>Status</th><th>Last Check</th><th>Actions</th></tr>';
  licenses.forEach(l => {
    const status = l.revoked ? '<span class="badge revoked">Revoked</span>' : '<span class="badge active">Active</span>';
    const lastCheck = l.last_check ? new Date(l.last_check).toLocaleDateString() : 'Never';
    const user = (l.user&&l.user.name) || 'Unknown';
    const actions = l.revoked 
      ? `<button class="success" onclick="unrevoke('${l.key}')">Re-enable</button>`
      : `<button class="danger" onclick="revoke('${l.key}')">Revoke</button>`;
    html += `<tr><td><code>${l.key}</code></td><td>${user}</td><td>${l.plan}</td><td>${status}</td><td>${lastCheck}</td><td class="actions">${actions}</td></tr>`;
  });
  html += '</table>';
  document.getElementById('licenseList').innerHTML = html;
}

async function createLicense() {
  const name = document.getElementById('newName').value;
  const email = document.getElementById('newEmail').value;
  const plan = document.getElementById('newPlan').value;
  if(!name) return show(document.getElementById('createResult'), 'Name is required', 'err');
  const r = await api('create', 'POST', {plan, user:{name, email}});
  const el = document.getElementById('createResult');
  if(r.ok) {
    show(el, `✅ License created: ${r.license_key}`, 'ok');
    document.getElementById('newName').value='';
    document.getElementById('newEmail').value='';
    loadAll();
  } else {
    show(el, 'Error: '+(r.error||'Unknown'), 'err');
  }
}

async function revoke(key) {
  if(!confirm('Revoke '+key+'? This will stop their software.')) return;
  const r = await api('revoke', 'POST', {license_key:key});
  if(r.ok) { loadAll(); show(document.getElementById('statusMsg'), 'License revoked', 'ok'); }
}

async function unrevoke(key) {
  const r = await api('unrevoke', 'POST', {license_key:key});
  if(r.ok) { loadAll(); show(document.getElementById('statusMsg'), 'License re-enabled', 'ok'); }
}

async function loadLogs() {
  const filter = document.getElementById('logFilter').value;
  let endpoint = 'logs?limit=50';
  if(filter) endpoint += '&key='+encodeURIComponent(filter);
  const r = await api(endpoint);
  if(!r.ok) return;
  const logs = r.logs||[];
  if(!logs.length) {
    document.getElementById('logList').innerHTML = '<div class="card"><p style="color:#64748b">No logs yet.</p></div>';
    return;
  }
  let html = '';
  logs.reverse().forEach(l => {
    const time = l.timestamp || l.received_at;
    html += `<div class="log-entry"><span class="time">${time}</span> — <span class="event">${l.event}</span> — Key: <code>${l.license_key}</code> — ${JSON.stringify(l.details||{})}</div>`;
  });
  document.getElementById('logList').innerHTML = html;
}

// Auto-login if token in URL hash
if(location.hash.startsWith('#token=')) {
  TOKEN = location.hash.replace('#token=','');
  login();
}
</script>
</body></html>'''
    return html


# ── START ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🔑 RR License Server running on port {port}")
    print(f"   Admin token: {ADMIN_TOKEN}")
    print(f"   Data file: {DATA_FILE}")
    app.run(host="0.0.0.0", port=port, debug=False)
