#!/usr/bin/env python3
"""WAHA Dashboard Multi-User"""
from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import APP_ROOT, PORT, SECRET_KEY
from db import close_db, current_user, init_db

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


@app.teardown_appcontext
def _close_db(_e):
    close_db(_e)


@app.context_processor
def inject_globals():
    user = current_user()
    app_root = request.script_root or APP_ROOT
    return {"app_root": app_root, "nav_avatar": user["avatar_path"] if user else None}


init_db()

from routes import register_routes  # noqa: E402

register_routes(app)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
