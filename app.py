from __future__ import annotations

import logging
import os
import sys
import threading
import time
import warnings
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

import oauth as token_source
from config import default_env, env_config, known_envs
from settings import load_settings
from shared_docs import register_howto
from shared_http import make_session
from shared_okta_auth import from_env_or_keyring

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("okta-live-tail")

KEYRING_SERVICE = "okta-live-tail"

load_dotenv(Path(__file__).parent / ".env")

APP_VERSION = "0.1.19"

UNIT_ALIASES: dict[str, str] = {}

# Raises SettingsError (naming the setting) when auth or the session key is unset
# and AUTH_MODE=none was not chosen explicitly.
settings = load_settings()
OIDC_SCOPES = "openid email profile"
BUFFER_SIZE = settings.buffer_size
DEDUP_RING_SIZE = settings.dedup_ring_size


def _build_orgs() -> dict[str, dict]:
    """Orgs come from the single config file (LIVE_TAIL_CONFIG), any number of them."""
    orgs = {}
    for key in known_envs():
        cfg = env_config(key)
        orgs[key] = {
            "label": cfg.get("label") or key.upper(),
            "url": cfg["url"].rstrip("/"),
            "token_var": cfg.get("token_var") or f"OKTA_LIVE_TAIL_{key.upper()}_API_TOKEN",
            "auth_mode": os.environ.get(f"OKTA_LIVE_TAIL_{key.upper()}_AUTH_MODE", "oauth"),
        }
    return orgs


ENV_CONFIGS: dict[str, dict] = _build_orgs()
DEFAULT_ENV = settings.default_env or default_env()

if settings.auth_mode == "none":
    log.warning("AUTH_MODE=none — auth gate disabled, app is open.")
if not settings.verify_tls:
    log.warning("OKTA_VERIFY_TLS is off — TLS certificates are NOT verified.")
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

app = Flask(__name__)
app.secret_key = settings.secret_key
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = settings.app_base_url.startswith("https://")
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = OAuth(app)
if settings.auth_mode == "oidc":
    oauth.register(
        name="oidc",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=f"{settings.oidc_issuer}/.well-known/openid-configuration",
        client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
    )

PUBLIC_PATHS = {
    "/health",
    "/login",
    "/oidc/login",
    "/oidc/callback",
    "/logout",
    "/favicon.ico",
}


def safe_next(nxt: str | None) -> str:
    """Accept only a same-site relative path; anything else becomes '/'."""
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return "/"
    if "\\" in nxt or any(ord(c) < 32 for c in nxt):
        return "/"
    parts = urlsplit(nxt)
    if parts.scheme or parts.netloc:
        return "/"
    return nxt


def is_authorized(email: str | None) -> bool:
    """True when the signed-in email is on the allow-list (address or domain)."""
    addr = (email or "").strip().lower()
    if "@" not in addr:
        return False
    return addr in settings.allowed_emails or addr.rsplit("@", 1)[1] in settings.allowed_domains


@app.before_request
def _auth_gate():
    start_workers()
    if settings.auth_mode == "none":
        return
    if request.path.startswith("/static/") or request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized — session expired"), 401
        return redirect(url_for("login", next=request.path))


def get_token(var_name: str) -> str:
    v = from_env_or_keyring(var_name, KEYRING_SERVICE)
    if not v:
        log.warning("get_token: no value found for %s", var_name)
    return v


def okta_session(env: str) -> requests.Session:
    cfg = ENV_CONFIGS[env]
    s = make_session("LiveTail", APP_VERSION)
    s.verify = settings.verify_tls
    if cfg["auth_mode"] == "oauth":
        s.headers["Authorization"] = f"Bearer {token_source.access_token(env)}"
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
    }
    for env in ENV_CONFIGS
}


def _normalize_event(e: dict, apps_by_id: dict[str, dict] | None = None) -> dict:
    targets = e.get("target") or []
    actor = e.get("actor") or {}
    outcome = e.get("outcome") or {}
    client = e.get("client") or {}
    debug = (e.get("debugContext") or {}).get("debugData") or {}
    event_type = e.get("eventType") or ""
    sign_on_mode = (debug.get("signOnMode") or "").strip()

    _actor_for_type = e.get("actor") or {}
    _actor_type = (_actor_for_type.get("type") or "").strip()
    if _actor_type in ("PublicClientApp", "TrustedApp", "ServiceApp"):
        _resolved_app_id = _actor_for_type.get("id") or ""
    else:
        _at = next(
            (
                t
                for t in (e.get("target") or [])
                if (t or {}).get("type") in ("AppInstance", "OAuth2Client")
            ),
            None,
        )
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
    app_target = next(
        (t for t in targets if (t or {}).get("type") in ("AppInstance", "OAuth2Client")), None
    )

    if actor_type == "User":
        user_id = actor.get("id") or ""
        user_disp = actor.get("alternateId") or actor.get("displayName") or ""
        app_id = (app_target or {}).get("id") or ""
        app_name = (app_target or {}).get("displayName") or ""
    else:
        user_id = (user_target or {}).get("id") or ""
        user_disp = (
            (user_target or {}).get("alternateId") or (user_target or {}).get("displayName") or ""
        )
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
        for a in r.json() or []:
            aid = a.get("id")
            label = a.get("label") or a.get("name") or ""
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
        except Exception:  # noqa: BLE001 - background loop boundary; logged, retried next cycle
            log.exception("[%s] apps refresh error", env)
        time.sleep(settings.apps_refresh_seconds)


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


def error_summary(exc: BaseException) -> str:
    """Client-safe error text: an HTTP error keeps its status, nothing else leaks."""
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return f"Okta HTTP error {exc.response.status_code}"
    return f"{type(exc).__name__} (see server log)"


def _poll_loop(env: str) -> None:
    state = _env_state[env]
    state["cursor"] = datetime.now(timezone.utc) - timedelta(
        minutes=settings.initial_lookback_minutes
    )
    try:
        _refresh_apps(env)
    except Exception:  # noqa: BLE001 - logged; the apps loop retries
        log.exception("[%s] initial apps refresh failed (will retry in apps loop)", env)
    log.info(
        "[%s] poll loop starting (interval=%ds, lookback=%dmin)",
        env,
        settings.poll_interval_seconds,
        settings.initial_lookback_minutes,
    )
    while True:
        try:
            since = state["cursor"]
            events, _ = _fetch_logs(env, since)
            added = _ingest(env, events)
            if events:
                latest = max(
                    (
                        datetime.fromisoformat(e["published"].replace("Z", "+00:00"))
                        for e in events
                        if e.get("published")
                    ),
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
        except Exception as e:  # noqa: BLE001 - background loop boundary; logged, retried
            log.exception("[%s] poll error", env)
            with _state_lock:
                state["last_error"] = error_summary(e)
        time.sleep(settings.poll_interval_seconds)


def _matches(ev: dict, tokens: list[str]) -> bool:
    if not tokens:
        return True
    hay = " ".join(
        str(v)
        for v in (
            ev.get("user", ""),
            ev.get("user_id", ""),
            ev.get("user_display", ""),
            ev.get("app", ""),
            ev.get("app_id", ""),
            ev.get("event_type", ""),
            ev.get("reason", ""),
            ev.get("ip", ""),
            ev.get("request_uri", ""),
        )
    ).lower()
    return all(t in hay for t in tokens)


@app.route("/health")
def health():
    return jsonify(status="ok", version=APP_VERSION)


@app.route("/login")
def login():
    if settings.auth_mode == "none":
        session["user"] = {"email": "local-dev"}
        return redirect(url_for("index"))
    nxt = safe_next(request.args.get("next"))
    redirect_uri = settings.app_base_url + url_for("oidc_callback")
    return oauth.oidc.authorize_redirect(redirect_uri, state=nxt)


@app.route("/oidc/login")
def oidc_login():
    return login()


@app.route("/oidc/callback")
def oidc_callback():
    if settings.auth_mode == "none":
        return redirect(url_for("index"))
    try:
        token = oauth.oidc.authorize_access_token()
        userinfo = token.get("userinfo") or oauth.oidc.parse_id_token(token)
    except Exception:  # noqa: BLE001 - web boundary; logged, client gets a generic 401
        log.exception("OIDC callback failed")
        return "OIDC auth failed", 401
    if not is_authorized(userinfo.get("email")):
        log.warning("OIDC sign-in rejected: account not on the allow-list")
        return "Not authorized", 403
    session["user"] = {"email": userinfo.get("email"), "name": userinfo.get("name")}
    return redirect(safe_next(request.args.get("state")))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


register_howto(app, tool_name="Okta Live Tail")


@app.route("/")
def index():
    return render_template(
        "index.html",
        version=APP_VERSION,
        user=session.get("user") or {"email": "local-dev"},
        envs=list(ENV_CONFIGS.keys()),
        default_env=DEFAULT_ENV,
    )


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
    return jsonify(
        {
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
        }
    )


_workers_lock = threading.Lock()
_workers_started = False


def start_workers():
    """Start the pollers once per process (on first request, or at `python app.py`)."""
    global _workers_started
    with _workers_lock:
        if _workers_started:
            return
        _workers_started = True
    for env in ENV_CONFIGS:
        threading.Thread(target=_poll_loop, daemon=True, name=f"poller-{env}", args=(env,)).start()
        threading.Thread(target=_apps_loop, daemon=True, name=f"apps-{env}", args=(env,)).start()


if __name__ == "__main__":
    start_workers()
    app.run(host=settings.host, port=settings.port, debug=False)
