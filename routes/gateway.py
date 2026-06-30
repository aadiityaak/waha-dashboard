import json

from flask import Blueprint, request

from db import gateway_owner, get_db
from helpers import waha

bp = Blueprint("gateway", __name__)


@bp.route("/gateway/webhook/<session_name>", methods=["GET", "POST"])
def gateway_webhook(session_name):
    api_key = request.args.get("token", "").strip()
    owner = gateway_owner(session_name, api_key)
    if not owner:
        return {"error": "token invalid"}, 403
    payload = request.get_data(as_text=True) or "{}"
    event_type = "message"
    try:
        parsed = json.loads(payload) if payload else {}
        event_type = parsed.get("event") or parsed.get("eventType") or parsed.get("type") or "message"
    except Exception:
        parsed = None
    get_db().execute(
        "INSERT INTO gateway_events (user_id, session_name, event_type, payload) VALUES (?,?,?,?)",
        (owner["id"], session_name, event_type, payload if parsed is not None else json.dumps({"raw": payload})),
    )
    get_db().commit()
    return {"ok": True}


@bp.route("/gateway/<session_name>/status")
def gateway_status(session_name):
    api_key = request.headers.get("X-Api-Key", "") or request.args.get("api_key", "")
    owner = gateway_owner(session_name, api_key)
    if not owner:
        return {"error": "api key invalid"}, 403
    try:
        st, data = waha("GET", f"/api/sessions/{session_name}")
        return data, int(st), {"Content-Type": "application/json"}
    except Exception as e:
        return {"error": str(e)}, 500


@bp.route("/gateway/<session_name>/send-text", methods=["POST"])
def gateway_send_text(session_name):
    api_key = request.headers.get("X-Api-Key", "") or request.args.get("api_key", "") or request.form.get("api_key", "")
    owner = gateway_owner(session_name, api_key)
    if not owner:
        return {"error": "api key invalid"}, 403
    payload = request.get_json(silent=True) or request.form.to_dict()
    chat_id = (payload.get("chatId") or payload.get("to") or "").strip()
    text = (payload.get("text") or payload.get("message") or "").strip()
    if not chat_id or not text:
        return {"error": "chatId/to dan text/message wajib diisi"}, 400
    try:
        st, data = waha("POST", "/api/sendText", {"session": session_name, "chatId": chat_id, "text": text})
        return data, int(st), {"Content-Type": "application/json"}
    except Exception as e:
        return {"error": str(e)}, 500


@bp.route("/gateway/<session_name>/events")
def gateway_events(session_name):
    api_key = request.headers.get("X-Api-Key", "") or request.args.get("api_key", "")
    owner = gateway_owner(session_name, api_key)
    if not owner:
        return {"error": "api key invalid"}, 403
    limit = min(max(request.args.get("limit", 20, type=int), 1), 100)
    rows = get_db().execute(
        "SELECT event_type, payload, created_at FROM gateway_events WHERE user_id=? AND session_name=? ORDER BY id DESC LIMIT ?",
        (owner["id"], session_name, limit),
    ).fetchall()
    return {
        "session": session_name,
        "items": [
            {"event_type": row["event_type"], "created_at": row["created_at"], "payload": json.loads(row["payload"])}
            for row in rows
        ],
    }
