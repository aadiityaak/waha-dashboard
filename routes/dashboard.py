import json
import secrets
import urllib.error
import urllib.request

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db import current_user, ensure_user_api_key, get_db, public_base_url
from helpers import can_access_session, is_admin, login_required, waha

bp = Blueprint("dashboard", __name__)


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
    if not is_admin():
        owned = {
            row["waha_session_name"]
            for row in get_db().execute(
                "SELECT waha_session_name FROM sessions_map WHERE user_id=?",
                (session["user_id"],),
            ).fetchall()
        }
        sessions = [s for s in sessions if s.get("name") in owned]
    return render_template(
        "index.html",
        username=session.get("username"),
        role=session.get("role"),
        sessions=sessions,
        auto_qr=request.args.get("qr", ""),
        api_key=(user["api_key"] if user else ""),
    )


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
    return render_template(
        "docs.html",
        username=session.get("username"),
        role=session.get("role"),
        selected_session=session_name,
        api_key=(user["api_key"] if user else ""),
        gateway_base=public_base_url(),
    )


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
    if not name:
        flash("Nama session wajib diisi", "danger")
        return redirect(url_for("dashboard.index"))
    try:
        api_key = ensure_user_api_key(session["user_id"])
        webhook_url = f"{public_base_url()}/gateway/webhook/{name}?token={api_key}"
        st, _ = waha("POST", "/api/sessions/start", {"name": name, "config": {"webhook_url": webhook_url}})
        if st in (200, 201):
            get_db().execute(
                "INSERT OR IGNORE INTO sessions_map (user_id, waha_session_name) VALUES (?,?)",
                (session["user_id"], name),
            )
            get_db().commit()
        flash(
            f"Session '{name}' started. QR akan dibuka otomatis." if st in (200, 201) else f"Gagal start session (HTTP {st})",
            "success" if st in (200, 201) else "danger",
        )
        if st in (200, 201):
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
        return redirect(url_for("dashboard.index"))
    try:
        waha("DELETE", f"/api/sessions/{name}/stop")
        flash(f"Session '{name}' stopped", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dashboard.index"))


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
