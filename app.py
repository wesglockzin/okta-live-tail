from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask, jsonify, redirect, render_template, render_template_string,
    request, session, url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from shared_http import make_session
from shared_docs import register_howto

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s | %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("okta-live-tail")

try:
    import keyring as _keyring
    KEYRING_SERVICE = "okta-live-tail"
except ImportError:
    _keyring = None
    KEYRING_SERVICE = ""

load_dotenv(Path(__file__).parent / ".env")

APP_VERSION = "0.1.19"

UNIT_ALIASES: dict[str, str] = {}

FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5005").rstrip("/")
OIDC_SCOPES = "openid email profile"
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)

ENV_CONFIGS: dict[str, dict] = {
    "dev":  {"label": "DEV",  "url": "https://host.example.com", "token_var": "OKTA_LIVE_TAIL_DEV_API_TOKEN"},
    "stg":  {"label": "STG",  "url": "https://host.example.com", "token_var": "OKTA_LIVE_TAIL_STG_API_TOKEN"},
    "prod": {"label": "PROD", "url": "https://host.example.com", "token_var": "OKTA_LIVE_TAIL_PROD_API_TOKEN"},
}

AUTH_MODE: dict[str, str] = {
    "dev":  os.environ.get("OKTA_LIVE_TAIL_DEV_AUTH_MODE",  "oauth"),
    "stg":  os.environ.get("OKTA_LIVE_TAIL_STG_AUTH_MODE",  "oauth"),
    "prod": os.environ.get("OKTA_LIVE_TAIL_PROD_AUTH_MODE", "oauth"),
}
DEFAULT_ENV = os.environ.get("DEFAULT_ENV", "prod")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "12"))
BUFFER_SIZE = int(os.environ.get("BUFFER_SIZE", "500"))
DEDUP_RING_SIZE = int(os.environ.get("DEDUP_RING_SIZE", "5000"))
INITIAL_LOOKBACK_MINUTES = int(os.environ.get("INITIAL_LOOKBACK_MINUTES", "5"))
APPS_REFRESH_SECONDS = int(os.environ.get("APPS_REFRESH_SECONDS", "1800"))

if not OIDC_ENABLED:
    log.warning("OIDC is NOT configured — auth gate disabled, app is open.")

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_BASE_URL.startswith("https://")
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = OAuth(app)
if OIDC_ENABLED:
    oauth.register(
        name="okta",
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
    )

PUBLIC_PATHS = {
    "/health", "/login", "/oidc/login", "/oidc/callback", "/logout", "/favicon.ico",
}


@app.before_request
def _auth_gate():
    if not OIDC_ENABLED:
        return
    if request.path.startswith("/static/") or request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized — session expired"), 401
        return redirect(url_for("login", next=request.path))


def get_token(var_name: str) -> str:
    v = (os.environ.get(var_name) or "").strip()
    if v:
        return v
    if _keyring:
        try:
            v = _keyring.get_password(KEYRING_SERVICE, var_name) or ""
            if v.strip():
                return v.strip()
        except Exception:
            pass
    log.warning("get_token: no value found for %s", var_name)
    return ""


def okta_session(env: str) -> requests.Session:
    cfg = ENV_CONFIGS[env]
    s = make_session("LiveTail", APP_VERSION)
    s.verify = False
    if AUTH_MODE.get(env) == "oauth":
        import oauth
        s.headers["Authorization"] = f"Bearer {oauth.access_token(env)}"
    else:
        s.headers["Authorization"] = f"SSWS {get_token(cfg['token_var'])}"
    return s


_state_lock = threading.RLock()
_env_state: dict[str, dict] = {
    env: {
        "events": deque(maxlen=BUFFER_SIZE),
        "uuid_ring": deque(maxlen=DEDUP_RING_SIZE),
        "uuid_set": set(),
        "raw_by_uuid": {},
        "cursor": None,
        "last_poll_ts": None,
        "last_error": None,
        "poll_count": 0,
        "events_seen": 0,
        "apps_by_id": {},
        "apps_refreshed_at": None,
    } for env in ENV_CONFIGS
}


def _normalize_event(e: dict, apps_by_id: dict[str, dict] | None = None) -> dict:
    targets = e.get("target") or []
    actor = e.get("actor") or {}
    outcome = e.get("outcome") or {}
    client = e.get("client") or {}
    debug = ((e.get("debugContext") or {}).get("debugData") or {})
    event_type = e.get("eventType") or ""
    sign_on_mode = (debug.get("signOnMode") or "").strip()

    _actor_for_type = (e.get("actor") or {})
    _actor_type = (_actor_for_type.get("type") or "").strip()
    if _actor_type in ("PublicClientApp", "TrustedApp", "ServiceApp"):
        _resolved_app_id = _actor_for_type.get("id") or ""
    else:
        _at = next((t for t in (e.get("target") or [])
                    if (t or {}).get("type") in ("AppInstance", "OAuth2Client")), None)
        _resolved_app_id = (_at or {}).get("id") or ""
    _looked_up_sso = ((apps_by_id or {}).get(_resolved_app_id) or {}).get("sso_type")

    if event_type == "user.authentication.sso":
        if sign_on_mode == "OPENID_CONNECT":
            sso_type = "OIDC"
        elif sign_on_mode == "SAML 2.0":
            sso_type = "SAML"
        elif _looked_up_sso in ("SAML", "OIDC"):
            sso_type = _looked_up_sso
        else:
            sso_type = "SSO"
    elif event_type.startswith("app.oauth2"):
        sso_type = _looked_up_sso if _looked_up_sso in ("SAML", "OIDC") else "OIDC"
    elif event_type == "user.authentication.auth_via_IDP":
        sso_type = "auth_via_IDP"
    elif _looked_up_sso in ("SAML", "OIDC"):
        sso_type = _looked_up_sso
    else:
        sso_type = event_type

    actor_type = (actor.get("type") or "").strip()
    user_target = next((t for t in targets if (t or {}).get("type") == "User"), None)
    app_target = next((t for t in targets
                       if (t or {}).get("type") in ("AppInstance", "OAuth2Client")), None)

    if actor_type == "User":
        user_id = actor.get("id") or ""
        user_disp = actor.get("alternateId") or actor.get("displayName") or ""
        app_id = (app_target or {}).get("id") or ""
        app_name = (app_target or {}).get("displayName") or ""
    else:
        user_id = (user_target or {}).get("id") or ""
        user_disp = (user_target or {}).get("alternateId") \
                    or (user_target or {}).get("displayName") or ""
        app_id = actor.get("id") or ""
        app_name = actor.get("displayName") or actor.get("alternateId") or ""
    if app_name.startswith("http://") or app_name.startswith("https://"):
        if app_id and apps_by_id:
            friendly = (apps_by_id.get(app_id) or {}).get("label")
            if friendly:
                app_name = friendly

    aliased = UNIT_ALIASES.get(app_name)
    if aliased:
        app_name = aliased

    return {
        "uuid": e.get("uuid") or "",
        "published": e.get("published") or "",
        "event_type": event_type,
        "sso_type": sso_type,
        "user": user_disp,
        "user_id": user_id,
        "user_display": user_disp,
        "app": app_name,
        "app_id": app_id,
        "result": outcome.get("result") or "",
        "reason": outcome.get("reason") or "",
        "ip": client.get("ipAddress") or "",
        "request_uri": debug.get("requestUri") or "",
        "sign_on_mode": sign_on_mode,
    }


def _ingest(env: str, raw_events: list[dict]) -> int:
    if not raw_events:
        return 0
    state = _env_state[env]
    added = 0
    with _state_lock:
        apps_by_id = state["apps_by_id"]
        for e in raw_events:
            uuid = e.get("uuid") or ""
            if not uuid or uuid in state["uuid_set"]:
                continue
            state["events"].appendleft(_normalize_event(e, apps_by_id))
            ring = state["uuid_ring"]
            if len(ring) == ring.maxlen:
                evicted = ring[0]
                state["uuid_set"].discard(evicted)
                state["raw_by_uuid"].pop(evicted, None)
            ring.append(uuid)
            state["uuid_set"].add(uuid)
            state["raw_by_uuid"][uuid] = e
            added += 1
        state["events_seen"] += added
    return added


def _signon_mode_to_sso_type(mode: str) -> str:
    m = (mode or "").upper()
    if m in ("OPENID_CONNECT",):
        return "OIDC"
    if m in ("SAML_2_0", "SAML_1_1"):
        return "SAML"
    return "OTHER"


def _refresh_apps(env: str) -> int:
    cfg = ENV_CONFIGS[env]
    s = okta_session(env)
    url = f"{cfg['url']}/api/v1/apps?limit=200"
    new_map: dict[str, dict] = {}
    pages = 0
    while url and pages < 20:
        r = s.get(url, timeout=30)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After") or "5")
            log.warning("[%s] apps refresh 429 — sleeping %ss", env, wait)
            time.sleep(min(wait, 30))
            break
        r.raise_for_status()
        for a in (r.json() or []):
            aid = a.get("id"); label = a.get("label") or a.get("name") or ""
            if aid:
                new_map[aid] = {
                    "label": label,
                    "sso_type": _signon_mode_to_sso_type(a.get("signOnMode") or ""),
                }
        url = None
        link = r.headers.get("Link") or ""
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
                break
        pages += 1
    with _state_lock:
        _env_state[env]["apps_by_id"] = new_map
        _env_state[env]["apps_refreshed_at"] = datetime.now(timezone.utc)
    log.info("[%s] apps_by_id refreshed: %d entries", env, len(new_map))
    return len(new_map)


def _apps_loop(env: str) -> None:
    while True:
        try:
            _refresh_apps(env)
        except Exception:
            log.exception("[%s] apps refresh error", env)
        time.sleep(APPS_REFRESH_SECONDS)


def _fetch_logs(env: str, since: datetime) -> tuple[list[dict], str | None]:
    cfg = ENV_CONFIGS[env]
    s = okta_session(env)
    params = {
        "since": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "limit": 1000,
        "sortOrder": "ASCENDING",
    }
    url = f"{cfg['url']}/api/v1/logs"
    events: list[dict] = []
    pages = 0
    while url and pages < 5:
        r = s.get(url, params=params if pages == 0 else None, timeout=30)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After") or "5")
            log.warning("[%s] 429 — sleeping %ss", env, wait)
            time.sleep(min(wait, 30))
            break
        r.raise_for_status()
        batch = r.json() or []
        events.extend(batch)
        url = None
        if len(batch) >= int(params.get("limit", 1000) or 1000):
            link = r.headers.get("Link") or ""
            for part in link.split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    break
        pages += 1
    return events, None


def _poll_loop(env: str) -> None:
    state = _env_state[env]
    state["cursor"] = datetime.now(timezone.utc) - timedelta(minutes=INITIAL_LOOKBACK_MINUTES)
    try:
        _refresh_apps(env)
    except Exception:
        log.exception("[%s] initial apps refresh failed (will retry in apps loop)", env)
    log.info("[%s] poll loop starting (interval=%ds, lookback=%dmin)",
             env, POLL_INTERVAL_SECONDS, INITIAL_LOOKBACK_MINUTES)
    while True:
        try:
            since = state["cursor"]
            events, _ = _fetch_logs(env, since)
            added = _ingest(env, events)
            if events:
                latest = max(
                    (datetime.fromisoformat(e["published"].replace("Z", "+00:00"))
                     for e in events if e.get("published")),
                    default=None,
                )
                if latest:
                    state["cursor"] = latest
            with _state_lock:
                state["last_poll_ts"] = datetime.now(timezone.utc)
                state["poll_count"] += 1
                state["last_error"] = None
            if added:
                log.info("[%s] +%d (buffer=%d)", env, added, len(state["events"]))
        except Exception as e:
            log.exception("[%s] poll error", env)
            with _state_lock:
                state["last_error"] = str(e)[:200]
        time.sleep(POLL_INTERVAL_SECONDS)


def _matches(ev: dict, tokens: list[str]) -> bool:
    if not tokens:
        return True
    hay = " ".join(str(v) for v in (
        ev.get("user", ""), ev.get("user_id", ""), ev.get("user_display", ""),
        ev.get("app", ""), ev.get("app_id", ""),
        ev.get("event_type", ""), ev.get("reason", ""),
        ev.get("ip", ""), ev.get("request_uri", ""),
    )).lower()
    return all(t in hay for t in tokens)


@app.route("/health")
def health():
    return jsonify(status="ok", version=APP_VERSION)


@app.route("/login")
def login():
    if not OIDC_ENABLED:
        session["user"] = {"email": "local-dev"}
        return redirect(url_for("index"))
    nxt = request.args.get("next", "/")
    redirect_uri = APP_BASE_URL + url_for("oidc_callback")
    return oauth.okta.authorize_redirect(redirect_uri, state=nxt)


@app.route("/oidc/login")
def oidc_login():
    return login()


@app.route("/oidc/callback")
def oidc_callback():
    if not OIDC_ENABLED:
        return redirect(url_for("index"))
    try:
        token = oauth.okta.authorize_access_token()
        userinfo = token.get("userinfo") or oauth.okta.parse_id_token(token)
        session["user"] = {
            "email": userinfo.get("email"),
            "name": userinfo.get("name"),
        }
    except Exception:
        log.exception("OIDC callback failed")
        return "OIDC auth failed", 401
    nxt = request.args.get("state") or "/"
    return redirect(nxt if nxt.startswith("/") else "/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


register_howto(app, tool_name="Okta Live Tail")


@app.route("/")
def index():
    return render_template("index.html",
                           version=APP_VERSION,
                           user=session.get("user") or {"email": "local-dev"},
                           envs=list(ENV_CONFIGS.keys()),
                           default_env=DEFAULT_ENV)


@app.route("/api/events/raw/<uuid>")
def api_event_raw(uuid: str):
    env = request.args.get("env", DEFAULT_ENV)
    if env not in ENV_CONFIGS:
        return jsonify(error=f"unknown env {env!r}"), 400
    state = _env_state[env]
    with _state_lock:
        raw = state["raw_by_uuid"].get(uuid)
    if raw is None:
        return jsonify(error="event not found (may have been evicted)", uuid=uuid), 404
    return jsonify(raw)


@app.route("/api/events")
def api_events():
    env = request.args.get("env", DEFAULT_ENV)
    if env not in ENV_CONFIGS:
        return jsonify(error=f"unknown env {env!r}"), 400
    q = (request.args.get("q") or "").strip().lower()
    tokens = [t for t in q.split() if t]
    state = _env_state[env]
    with _state_lock:
        rows = [ev for ev in state["events"] if _matches(ev, tokens)]
        poll_ts = state["last_poll_ts"]
        last_err = state["last_error"]
        seen = state["events_seen"]
        buffer_len = len(state["events"])
    return jsonify({
        "env": env,
        "version": APP_VERSION,
        "rows": rows,
        "meta": {
            "buffer_len": buffer_len,
            "events_seen": seen,
            "last_poll": poll_ts.isoformat() if poll_ts else None,
            "last_error": last_err,
            "filter_tokens": tokens,
        },
    })


def start_workers():
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass
    for env in ENV_CONFIGS:
        threading.Thread(target=_poll_loop, daemon=True,
                         name=f"poller-{env}", args=(env,)).start()
        threading.Thread(target=_apps_loop, daemon=True,
                         name=f"apps-{env}", args=(env,)).start()


start_workers()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5005))
    app.run(host="0.0.0.0", port=port, debug=False)
