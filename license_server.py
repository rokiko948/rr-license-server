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


# ── START ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🔑 RR License Server running on port {port}")
    print(f"   Admin token: {ADMIN_TOKEN}")
    print(f"   Data file: {DATA_FILE}")
    app.run(host="0.0.0.0", port=port, debug=False)
