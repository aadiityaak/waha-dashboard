import json
import re
import secrets

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db import current_user, ensure_user_api_key, get_db, public_base_url
from helpers import can_access_session, is_admin, login_required, waha

bp = Blueprint("dashboard", __name__)


def _status_data():
    import os, subprocess
    apps = [
        ("Nginx", 80, "nginx"),
        ("Waha Dashboard", 8084, "python3 .*app.py"),
        ("WAHA", 3001, "waha|node.*3001"),
        ("Map API", 8094, "python3 .*8094"),
        ("Telegram Broadcast", 8080, "telegram_broadcast_api"),
    ]
    ss = subprocess.run(["bash","-lc","ss -tlnp"], capture_output=True, text=True).stdout
    ps = subprocess.run(["bash","-lc","ps -eo pid=,cmd= | sed -n '1,200p'"], capture_output=True, text=True).stdout
    rows=[]
    for name, port, pat in apps:
        running = f':{port} ' in ss or port == 80 and ':80 ' in ss or port == 443 and ':443 ' in ss
        pid = "-"
        for line in ps.splitlines():
            if pat in line:
                pid = line.strip().split(None,1)[0]
                break
        rows.append({"name":name,"port":port,"pid":pid,"running":running,"note":""})
    mem = subprocess.run(["bash","-lc","free -h | awk 'NR==2{print $3 \" / \" $2 \" (\" $7 \" available)\"}'"], capture_output=True, text=True).stdout.strip()
    uptime = subprocess.run(["bash","-lc","uptime -p"], capture_output=True, text=True).stdout.strip().replace('up ','')
    load = subprocess.run(["bash","-lc","uptime | awk -F'load average: ' '{print $2}'"], capture_output=True, text=True).stdout.strip()
    return rows, mem, uptime, load


@bp.route("/status")
def status_home():
    apps, mem, uptime, load = _status_data()
    return render_template("status_home.html", apps=apps, mem=mem, uptime=uptime, load=load, username=session.get("username"), role=session.get("role"))


@bp.route("/")
@login_required
def index():
    data = "[]"
    user = current_user()
    if user:
        ensure_user_api_key(user["id"])
        user = current_user()
    try:
        _, data = waha("GET", "/api/sessions")
    except Exception as e:
        flash(f"Gagal konek WAHA: {e}", "danger")
    sessions = json.loads(data) if isinstance(data, str) else []
    owner_rows = get_db().execute("SELECT u.username, m.waha_session_name FROM sessions_map m JOIN users u ON u.id = m.user_id").fetchall()
    owner_map = {row["waha_session_name"]: row["username"] for row in owner_rows}
    sessions = [s for s in sessions if s.get("name") != "sesi baru"]
    for s in sessions:
        s["owner"] = owner_map.get(s.get("name"), "-")
    users = get_db().execute("SELECT id, username FROM users ORDER BY username").fetchall()
    if not is_admin():
        owned = {row["waha_session_name"] for row in get_db().execute("SELECT waha_session_name FROM sessions_map WHERE user_id=?", (session["user_id"],)).fetchall()}
        sessions = [s for s in sessions if s.get("name") in owned]
        users = [u for u in users if u["id"] == session["user_id"]]
    return render_template("index.html", username=session.get("username"), role=session.get("role"), sessions=sessions, users=users, auto_qr=request.args.get("qr", ""), api_key=(user["api_key"] if user else ""))


@bp.route("/logs/<session_name>")
@login_required
def logs(session_name):
    if not can_access_session(session_name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("dashboard.index"))
    rows = get_db().execute("SELECT event_type, payload, created_at FROM gateway_events WHERE session_name=? ORDER BY id DESC LIMIT 50", (session_name,)).fetchall()
    return render_template("logs.html", username=session.get("username"), role=session.get("role"), session_name=session_name, rows=rows)


@bp.route("/docs")
@login_required
def docs():
    user = current_user()
    session_name = request.args.get("session", "").strip()
    if session_name and not can_access_session(session_name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("dashboard.docs"))
    if user:
        ensure_user_api_key(user["id"])
        user = current_user()
    return render_template("docs.html", username=session.get("username"), role=session.get("role"), selected_session=session_name, api_key=(user["api_key"] if user else ""), gateway_base=public_base_url())


@bp.route("/docs/test-send", methods=["POST"])
@login_required
def docs_test_send():
    if not current_user():
        return {"error": "unauthorized"}, 401
    session_name = request.form.get("session_name", "").strip()
    chat_id = request.form.get("chatId", "").strip()
    text = request.form.get("text", "").strip()
    if not session_name or not can_access_session(session_name):
        return {"ok": False, "error": "Akses session ditolak"}, 403
    if not chat_id or not text:
        return {"ok": False, "error": "Nomor dan isi pesan wajib diisi"}, 400
    try:
        st, data = waha("POST", "/api/sendText", {"session": session_name, "chatId": chat_id, "text": text})
        return data, int(st), {"Content-Type": "application/json"}
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500


@bp.route("/me/api-key/regenerate", methods=["POST"])
@login_required
def api_key_regenerate():
    api_key = secrets.token_hex(16)
    get_db().execute("UPDATE users SET api_key=? WHERE id=?", (api_key, session["user_id"]))
    get_db().commit()
    flash("API key baru berhasil dibuat", "success")
    session_name = request.form.get("session_name", "").strip()
    return_to = request.form.get("return_to", "docs").strip()
    if return_to == "index":
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("dashboard.docs", session=session_name) if session_name else url_for("dashboard.docs"))


@bp.route("/session/start", methods=["POST"])
@login_required
def session_start():
    name = request.form.get("name", "").strip()
    user_id = request.form.get("user_id", "").strip()
    if not name:
        flash("Nama Session wajib diisi", "danger")
        return redirect(url_for("dashboard.index"))
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        flash("Nama Session cuma huruf, angka, underscore. Tanpa spasi/simbol.", "danger")
        return redirect(url_for("dashboard.index"))
    try:
        target_user = user_id or str(session["user_id"])
        api_key = ensure_user_api_key(int(target_user))
        st, body = waha("POST", "/api/sessions/start", {"name": name})
        started_ok = st in (200, 201) or (st == 422 and "already started" in (body or "").lower())
        if started_ok:
            get_db().execute("INSERT OR IGNORE INTO sessions_map (user_id, waha_session_name) VALUES (?,?)", (int(target_user), name))
            get_db().commit()
        flash(f"Session '{name}' started. QR akan dibuka otomatis." if started_ok else f"Gagal start session (HTTP {st}): {body[:200]}", "success" if started_ok else "danger")
        if started_ok:
            return redirect(url_for("dashboard.index", qr=name))
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dashboard.index"))


@bp.route("/session/stop", methods=["POST"])
@login_required
def session_stop():
    name = request.form.get("name", "")
    if not can_access_session(name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("dashboard.index", r=secrets.token_hex(4), _external=False))
    try:
        waha("DELETE", f"/api/sessions/{name}")
        flash(f"Session '{name}' stopped", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dashboard.index", r=secrets.token_hex(4)))


@bp.route("/session/qr/<name>")
@login_required
def session_qr(name):
    if not can_access_session(name):
        return {"error": "Akses session ditolak"}, 403
    try:
        st, data = waha("GET", f"/api/{name}/auth/qr")
        if int(st) != 200:
            return data, int(st), {"Content-Type": "application/json"}
        payload = json.loads(data) if isinstance(data, str) else data
        if payload.get("data") and payload.get("mimetype"):
            return {"qr": f"data:{payload['mimetype']};base64,{payload['data']}"}, 200
        if payload.get("qr") or payload.get("code"):
            return payload, 200
        status_st, status_data = waha("GET", f"/api/sessions/{name}")
        if int(status_st) == 200:
            status_payload = json.loads(status_data) if isinstance(status_data, str) else status_data
            return {"status": status_payload.get("status", "UNKNOWN"), "message": "Session sudah aktif, QR tidak tersedia"}, 200
        return {"error": "QR belum tersedia", "raw": payload}, 404
    except Exception as e:
        return {"error": str(e)}, 500


@bp.route("/session/status/<name>")
@login_required
def session_status(name):
    if not can_access_session(name):
        return {"error": "Akses session ditolak"}, 403
    try:
        st, data = waha("GET", f"/api/sessions/{name}")
        return data, int(st), {"Content-Type": "application/json"}
    except Exception as e:
        return {"error": str(e)}, 500


@bp.route("/session/logout", methods=["POST"])
@login_required
def session_logout():
    name = request.form.get("name", "")
    if not can_access_session(name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("dashboard.index"))
    try:
        waha("DELETE", f"/api/sessions/{name}/logout")
        flash(f"Session '{name}' logged out", "info")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dashboard.index"))


@bp.route("/session/delete", methods=["POST"])
@login_required
def session_delete():
    name = request.form.get("name", "")
    if not can_access_session(name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("dashboard.index"))
    try:
        waha("DELETE", f"/api/sessions/{name}")
        get_db().execute("DELETE FROM sessions_map WHERE waha_session_name=?", (name,))
        get_db().commit()
        flash(f"Session '{name}' deleted", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dashboard.index"))
