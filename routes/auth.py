import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db import current_user, get_db, hash_password, verify_password

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
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
                return render_template("login.html", username=session.get("username"), role=session.get("role"))
            if needs_upgrade:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(raw_password), row["id"]))
                db.commit()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            flash("Login berhasil", "success")
            return redirect(url_for("dashboard.index"))
        flash("Username atau password salah", "danger")
    return render_template("login.html", username=session.get("username"), role=session.get("role"))


@bp.route("/logout")
def logout():
    session.clear()
    flash("Logout berhasil", "info")
    return redirect(url_for("auth.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        if not u or not p:
            flash("Username dan password wajib diisi", "danger")
            return render_template("register.html", username=session.get("username"), role=session.get("role"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (u, hash_password(p)))
            db.commit()
            flash("Registrasi berhasil, silakan login", "success")
            return redirect(url_for("auth.login"))
        except sqlite3.IntegrityError:
            flash("Username sudah dipakai", "danger")
    return render_template("register.html", username=session.get("username"), role=session.get("role"))


@bp.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        flash("Silakan login dulu", "warning")
        return redirect(url_for("auth.login"))
    user = current_user()
    if not user:
        session.clear()
        flash("Session user tidak valid", "danger")
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        username = request.form["username"].strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not username:
            flash("Username wajib diisi", "danger")
            return render_template("profile.html", profile_user=user, username=session.get("username"), role=session.get("role"))
        updates = []
        params = []
        if username != user["username"]:
            updates.append("username=?")
            params.append(username)
        if new_password or confirm_password or current_password:
            ok, _ = verify_password(get_db().execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()["password_hash"], current_password)
            if not ok:
                flash("Password saat ini salah", "danger")
                return render_template("profile.html", profile_user=user, username=session.get("username"), role=session.get("role"))
            if len(new_password) < 6:
                flash("Password baru minimal 6 karakter", "danger")
                return render_template("profile.html", profile_user=user, username=session.get("username"), role=session.get("role"))
            if new_password != confirm_password:
                flash("Konfirmasi password baru tidak cocok", "danger")
                return render_template("profile.html", profile_user=user, username=session.get("username"), role=session.get("role"))
            updates.append("password_hash=?")
            params.append(hash_password(new_password))
        if not updates:
            flash("Tidak ada perubahan", "info")
            return redirect(url_for("auth.profile"))
        params.append(user["id"])
        try:
            get_db().execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", tuple(params))
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("Username sudah dipakai", "danger")
            return render_template("profile.html", profile_user=user, username=session.get("username"), role=session.get("role"))
        session["username"] = username
        flash("Profil berhasil diperbarui", "success")
        return redirect(url_for("auth.profile"))
    return render_template("profile.html", profile_user=user, username=session.get("username"), role=session.get("role"))
