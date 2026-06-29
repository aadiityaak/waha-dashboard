# WAHA Multi-User Dashboard

Custom dashboard for WAHA.

## Stack
- Flask
- SQLite
- Bootstrap 5 CDN

## Features
- Multi-user login/register
- Admin/user roles
- WAHA session list
- Start/stop/logout session
- QR modal for scan flow

## Setup
1. Create venv.
2. Install deps: `pip install flask httpx`
3. Copy `.env.example` to `.env`
4. Set `WAHA_API_KEY`, `WAHA_DASH_SECRET`, admin creds.
5. Run: `python3 app.py`

## Environment
App reads config from environment variables. Do not commit real `.env` or SQLite DB.

## Default publish safety
- `.gitignore` excludes `.env`
- `.gitignore` excludes `*.db`
- app refuses WAHA calls if `WAHA_API_KEY` unset
- password hash uses Werkzeug secure hash (`scrypt` default)
- legacy SHA256 hashes auto-upgrade on next successful login
