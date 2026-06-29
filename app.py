#!/usr/bin/env python3
"""WAHA Dashboard Multi-User"""
import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
from functools import wraps

import httpx
from flask import Flask, flash, g, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(__file__)
WAHA_URL = os.environ.get("WAHA_URL", "http://127.0.0.1:3001")
WAHA_API_KEY = os.environ.get("WAHA_API_KEY", "")
DB = os.path.join(BASE_DIR, "waha_users.db")
SECRET_KEY = os.environ.get("WAHA_DASH_SECRET") or secrets.token_hex(32)
PORT = int(os.environ.get("PORT", "8084"))
ADMIN_USERNAME = os.environ.get("WAHA_DASH_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("WAHA_DASH_ADMIN_PASSWORD", "")
APP_ROOT = os.environ.get("APP_ROOT", "")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_hash: str, password: str) -> tuple[bool, bool]:
    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_hash, password), False
    legacy_ok = stored_hash == hashlib.sha256(password.encode()).hexdigest()
    return legacy_ok, legacy_ok


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(_e):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS sessions_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        waha_session_name TEXT NOT NULL,
        UNIQUE(user_id, waha_session_name)
    )"""
    )
    if ADMIN_PASSWORD:
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD), "admin"),
            )
        except sqlite3.IntegrityError:
            pass
    db.commit()
    db.close()


init_db()


def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            flash("Silakan login dulu", "warning")
            return redirect(url_for("login"))
        return f(*a, **kw)

    return dec


def admin_required(f):
    @wraps(f)
    @login_required
    def dec(*a, **kw):
        u = get_db().execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not u or u["role"] != "admin":
            flash("Akses ditolak", "danger")
            return redirect(url_for("index"))
        return f(*a, **kw)

    return dec


def is_admin() -> bool:
    return session.get("role") == "admin"


def can_access_session(name: str) -> bool:
    if is_admin():
        return True
    row = get_db().execute(
        "SELECT 1 FROM sessions_map WHERE user_id=? AND waha_session_name=?",
        (session.get("user_id"), name),
    ).fetchone()
    return bool(row)


async def awaha(method, path, json_data=None):
    async with httpx.AsyncClient(base_url=WAHA_URL) as cl:
        headers = {"X-Api-Key": WAHA_API_KEY, "Accept": "application/json"}
        if json_data is not None:
            headers["Content-Type"] = "application/json"
        r = await cl.request(method, path, headers=headers, json=json_data, timeout=30)
        return r.status_code, r.text


def waha(method, path, json_data=None):
    if not WAHA_API_KEY:
        raise RuntimeError("WAHA_API_KEY belum diset")
    return asyncio.run(awaha(method, path, json_data))


@app.context_processor
def inject_globals():
    return {"app_root": APP_ROOT}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"].strip()
        raw_password = request.form["password"]
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row:
            ok, needs_upgrade = verify_password(row["password_hash"], raw_password)
            if not ok:
                flash("Username atau password salah", "danger")
                return render_template_string(LOGIN_TPL, username=session.get("username"), role=session.get("role"))
            if needs_upgrade:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(raw_password), row["id"]))
                db.commit()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            flash("Login berhasil", "success")
            return redirect(url_for("index"))
        flash("Username atau password salah", "danger")
    return render_template_string(LOGIN_TPL, username=session.get("username"), role=session.get("role"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logout berhasil", "info")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        if not u or not p:
            flash("Username dan password wajib diisi", "danger")
            return render_template_string(REGISTER_TPL, username=session.get("username"), role=session.get("role"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (u, hash_password(p)))
            db.commit()
            flash("Registrasi berhasil, silakan login", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username sudah dipakai", "danger")
    return render_template_string(REGISTER_TPL, username=session.get("username"), role=session.get("role"))


@app.route("/")
@login_required
def index():
    data = "[]"
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
    return render_template_string(
        INDEX_TPL,
        username=session.get("username"),
        role=session.get("role"),
        sessions=sessions,
    )


@app.route("/users")
@admin_required
def users_list():
    db = get_db()
    rows = db.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    mapped = db.execute(
        """SELECT sm.waha_session_name, u.username
        FROM sessions_map sm JOIN users u ON u.id = sm.user_id
        ORDER BY sm.waha_session_name, u.username"""
    ).fetchall()
    session_names = []
    try:
        _, data = waha("GET", "/api/sessions")
        session_names = sorted({s.get("name") for s in json.loads(data) if s.get("name")})
    except Exception:
        pass
    return render_template_string(
        USERS_TPL,
        username=session.get("username"),
        role=session.get("role"),
        users=rows,
        mapped=mapped,
        session_names=session_names,
    )


@app.route("/users/create", methods=["POST"])
@admin_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not username or not password:
        flash("Username dan password wajib diisi", "danger")
        return redirect(url_for("users_list"))
    if role not in {"admin", "user"}:
        role = "user"
    try:
        get_db().execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (username, hash_password(password), role),
        )
        get_db().commit()
        flash(f"User '{username}' dibuat", "success")
    except sqlite3.IntegrityError:
        flash("Username sudah dipakai", "danger")
    return redirect(url_for("users_list"))


@app.route("/users/delete", methods=["POST"])
@admin_required
def users_delete():
    user_id = request.form.get("user_id", type=int)
    if not user_id:
        flash("User tidak valid", "danger")
        return redirect(url_for("users_list"))
    if user_id == session.get("user_id"):
        flash("Tidak bisa hapus user login sendiri", "danger")
        return redirect(url_for("users_list"))
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("users_list"))
    db.execute("DELETE FROM sessions_map WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash(f"User '{row['username']}' dihapus", "info")
    return redirect(url_for("users_list"))


@app.route("/sessions/assign", methods=["POST"])
@admin_required
def sessions_assign():
    user_id = request.form.get("user_id", type=int)
    session_name = request.form.get("session_name", "").strip()
    if not user_id or not session_name:
        flash("User dan session wajib dipilih", "danger")
        return redirect(url_for("users_list"))
    row = get_db().execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("users_list"))
    get_db().execute("DELETE FROM sessions_map WHERE waha_session_name=?", (session_name,))
    get_db().execute(
        "INSERT INTO sessions_map (user_id, waha_session_name) VALUES (?,?)",
        (user_id, session_name),
    )
    get_db().commit()
    flash(f"Session '{session_name}' di-assign ke '{row['username']}'", "success")
    return redirect(url_for("users_list"))


@app.route("/session/start", methods=["POST"])
@login_required
def session_start():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Nama session wajib diisi", "danger")
        return redirect(url_for("index"))
    try:
        st, _ = waha("POST", "/api/sessions/start", {"name": name, "config": {"webhook_url": ""}})
        if st in (200, 201):
            get_db().execute(
                "INSERT OR IGNORE INTO sessions_map (user_id, waha_session_name) VALUES (?,?)",
                (session["user_id"], name),
            )
            get_db().commit()
        flash(
            f"Session '{name}' started. Scan QR di halaman sessions." if st in (200, 201) else f"Gagal start session (HTTP {st})",
            "success" if st in (200, 201) else "danger",
        )
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/session/stop", methods=["POST"])
@login_required
def session_stop():
    name = request.form.get("name", "")
    if not can_access_session(name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("index"))
    try:
        waha("DELETE", f"/api/sessions/{name}/stop")
        flash(f"Session '{name}' stopped", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/session/qr/<name>")
@login_required
def session_qr(name):
    if not can_access_session(name):
        return {"error": "Akses session ditolak"}, 403
    try:
        st, data = waha("GET", f"/api/sessions/{name}/qr")
        return data, int(st), {"Content-Type": "application/json"}
    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/session/logout", methods=["POST"])
@login_required
def session_logout():
    name = request.form.get("name", "")
    if not can_access_session(name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("index"))
    try:
        waha("DELETE", f"/api/sessions/{name}/logout")
        flash(f"Session '{name}' logged out", "info")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("index"))


BASE = """<!doctype html>
<html lang="id" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WAHA Dashboard</title>
  <base href="{{ app_root }}/">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    body { background:#0f172a; }
    .card { background:#1e293b; border:1px solid #334155; }
    .form-control,.form-control:focus { background:#0f172a; border-color:#475569; color:#e2e8f0; }
    .btn-primary { background:#2563eb; border-color:#2563eb; }
    .btn-primary:hover { background:#1d4ed8; }
    .navbar { background:#1e293b; border-bottom:1px solid #334155; }
    .toast-container { z-index:9999; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg mb-4">
  <div class="container">
    <a class="navbar-brand fw-bold text-white" href="{{ app_root or '/' }}"><i class="bi bi-whatsapp"></i> WAHA</a>
    <div class="collapse navbar-collapse show">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="{{ app_root or '/' }}">Sessions</a></li>
        {% if role == 'admin' %}
        <li class="nav-item"><a class="nav-link" href="{{ app_root }}/users">Users</a></li>
        {% endif %}
      </ul>
      {% if username %}
      <span class="text-light-emphasis me-3"><i class="bi bi-person-circle"></i> {{ username }}</span>
      <a href="{{ app_root }}/logout" class="btn btn-outline-secondary btn-sm">Logout</a>
      {% endif %}
    </div>
  </div>
</nav>
<div class="container">
{% with msgs = get_flashed_messages(with_categories=true) %}
{% if msgs %}
<div class="toast-container position-fixed top-0 end-0 p-3">
{% for cat, msg in msgs %}
<div class="toast align-items-center text-bg-{{ 'danger' if cat=='danger' else 'success' if cat=='success' else 'warning' if cat=='warning' else 'info' }} border-0 show" role="alert">
<div class="d-flex"><div class="toast-body">{{ msg }}</div>
<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
</div></div>
{% endfor %}
</div>
{% endif %}
{% endwith %}
{% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>document.querySelectorAll('.toast').forEach(t => setTimeout(() => t.remove(), 5000))</script>
</body>
</html>"""

LOGIN_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-4"><div class="card p-4">
<h4 class="text-center mb-4"><i class="bi bi-whatsapp"></i> WAHA Login</h4>
<form method="post" action="{{ app_root }}/login">
<div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" class="form-control" required></div>
<button type="submit" class="btn btn-primary w-100">Login</button>
</form>
<p class="text-center mt-3 mb-0"><small><a href="{{ app_root }}/register">Register</a></small></p>
</div></div></div>
{% endblock %}""")

REGISTER_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-4"><div class="card p-4">
<h4 class="text-center mb-4">Register</h4>
<form method="post" action="{{ app_root }}/register">
<div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" class="form-control" required></div>
<button type="submit" class="btn btn-primary w-100">Daftar</button>
</form>
<p class="text-center mt-3 mb-0"><small><a href="{{ app_root }}/login">Sudah punya akun? Login</a></small></p>
</div></div></div>
{% endblock %}""")

INDEX_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
<h4 class="m-0"><i class="bi bi-phone"></i> Sessions</h4>
<button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#startModal"><i class="bi bi-plus-lg"></i> Start New</button>
</div>
<div class="row">
{% for s in sessions %}
<div class="col-md-6 col-lg-4 mb-3"><div class="card p-3 h-100">
<div class="d-flex justify-content-between align-items-start">
<div><h5 class="mb-1">{{ s.name }}</h5><small class="text-light-emphasis">{% if s.me %}{{ s.me }}{% else %}-{% endif %}</small></div>
<span class="badge {% if s.status == 'WORKING' %}bg-success{% elif s.status in ['STOPPED','FAILED'] %}bg-danger{% else %}bg-warning{% endif %}">{{ s.status }}</span>
</div><hr class="my-2 border-secondary"><div class="d-flex gap-2 flex-wrap">
{% if s.status == 'WORKING' %}
<form method="post" action="{{ app_root }}/session/stop" onsubmit="return confirm('Stop {{ s.name }}?')"><input type="hidden" name="name" value="{{ s.name }}"><button class="btn btn-outline-warning btn-sm"><i class="bi bi-stop-circle"></i> Stop</button></form>
<form method="post" action="{{ app_root }}/session/logout" onsubmit="return confirm('Logout {{ s.name }}?')"><input type="hidden" name="name" value="{{ s.name }}"><button class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right"></i> Logout</button></form>
{% elif s.status == 'SCAN_QR_CODE' %}
<button class="btn btn-outline-info btn-sm qr-btn" data-name="{{ s.name }}"><i class="bi bi-qr-code"></i> QR</button>
{% elif s.status in ['STOPPED','FAILED'] %}
<form method="post" action="{{ app_root }}/session/start"><input type="hidden" name="name" value="{{ s.name }}"><button class="btn btn-outline-success btn-sm"><i class="bi bi-play-circle"></i> Start</button></form>
{% endif %}
</div></div></div>
{% else %}
<div class="col-12"><div class="card p-5 text-center"><i class="bi bi-inbox display-6"></i><p class="mt-2">Belum ada session. Klik <strong>Start New</strong>.</p></div></div>
{% endfor %}
</div>
<div class="modal fade" id="startModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content" style="background:#1e293b;"><form method="post" action="{{ app_root }}/session/start">
<div class="modal-header border-secondary"><h5 class="modal-title">Start New Session</h5><button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><label class="form-label">Nama Session</label><input name="name" class="form-control" placeholder="misal: bisnis_1" required></div>
<div class="modal-footer border-secondary"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Batal</button><button type="submit" class="btn btn-primary">Start</button></div>
</form></div></div></div>
<div class="modal fade" id="qrModal" tabindex="-1"><div class="modal-dialog modal-sm"><div class="modal-content" style="background:#1e293b;">
<div class="modal-header border-secondary"><h5 class="modal-title">QR Code</h5><button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button></div>
<div class="modal-body text-center" id="qrBody"><div class="spinner-border"></div><p class="mt-2">Loading QR...</p></div>
</div></div></div>
<script>
const APP_ROOT = {{ app_root|tojson }};
document.querySelectorAll('.qr-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const name = btn.dataset.name;
    const modal = new bootstrap.Modal(document.getElementById('qrModal'));
    document.getElementById('qrBody').innerHTML = '<div class="spinner-border"></div><p class="mt-2">Loading QR...</p>';
    modal.show();
    try {
      const r = await fetch(APP_ROOT + '/session/qr/' + encodeURIComponent(name));
      const d = await r.json();
      if (d.qr) document.getElementById('qrBody').innerHTML = '<img src="' + d.qr + '" class="img-fluid" style="max-width:250px"><p class="mt-2 text-light-emphasis">Scan dengan WhatsApp</p>';
      else if (d.code) document.getElementById('qrBody').innerHTML = '<h2 class="fw-bold" style="letter-spacing:8px">' + d.code + '</h2><p class="mt-2 text-light-emphasis">Masukkan kode di WhatsApp</p>';
      else document.getElementById('qrBody').innerHTML = '<p class="text-warning">QR belum tersedia</p>';
    } catch(e) { document.getElementById('qrBody').innerHTML = '<p class="text-danger">Gagal load QR</p>'; }
  });
});
</script>
{% endblock %}""")

USERS_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<h4><i class="bi bi-people"></i> Users</h4>
<div class="row g-3 mt-1">
  <div class="col-lg-5">
    <div class="card p-3">
      <h5 class="mb-3">Buat User</h5>
      <form method="post" action="{{ app_root }}/users/create">
        <div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required></div>
        <div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" class="form-control" required></div>
        <div class="mb-3"><label class="form-label">Role</label><select name="role" class="form-select"><option value="user">user</option><option value="admin">admin</option></select></div>
        <button class="btn btn-primary w-100">Buat User</button>
      </form>
    </div>
    <div class="card p-3 mt-3">
      <h5 class="mb-3">Assign Session Lama</h5>
      <form method="post" action="{{ app_root }}/sessions/assign">
        <div class="mb-3"><label class="form-label">Session WAHA</label><select name="session_name" class="form-select" required>{% for name in session_names %}<option value="{{ name }}">{{ name }}</option>{% endfor %}</select></div>
        <div class="mb-3"><label class="form-label">Owner</label><select name="user_id" class="form-select" required>{% for u in users %}<option value="{{ u.id }}">{{ u.username }} ({{ u.role }})</option>{% endfor %}</select></div>
        <button class="btn btn-outline-info w-100">Assign</button>
      </form>
    </div>
  </div>
  <div class="col-lg-7">
    <div class="card p-0">
      <table class="table table-dark table-striped mb-0 align-middle">
        <thead><tr><th>ID</th><th>Username</th><th>Role</th><th style="width:1%">Aksi</th></tr></thead>
        <tbody>
        {% for u in users %}
        <tr>
          <td>{{ u.id }}</td>
          <td>{{ u.username }}</td>
          <td><span class="badge bg-{{ 'primary' if u.role=='admin' else 'secondary' }}">{{ u.role }}</span></td>
          <td>
            {% if u.id != session.user_id %}
            <form method="post" action="{{ app_root }}/users/delete" onsubmit="return confirm('Hapus user {{ u.username }}?')">
              <input type="hidden" name="user_id" value="{{ u.id }}">
              <button class="btn btn-outline-danger btn-sm">Hapus</button>
            </form>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    <div class="card p-3 mt-3">
      <h5 class="mb-3">Mapping Session</h5>
      <div class="table-responsive">
        <table class="table table-dark table-striped mb-0">
          <thead><tr><th>Session</th><th>Owner</th></tr></thead>
          <tbody>
          {% for m in mapped %}
          <tr><td>{{ m.waha_session_name }}</td><td>{{ m.username }}</td></tr>
          {% else %}
          <tr><td colspan="2" class="text-center text-light-emphasis">Belum ada mapping</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
{% endblock %}""")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=True)
