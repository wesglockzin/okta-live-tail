"""Environment-variable settings, validated once at startup."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


class SettingsError(RuntimeError):
    """A required setting is missing or invalid; the message names it."""


_FALSE = {"0", "false", "no", "off"}


def _required(environ: Mapping[str, str], name: str) -> str:
    value = (environ.get(name) or "").strip()
    if not value:
        raise SettingsError(f"required setting {name} is not set")
    return value


def _int(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise SettingsError(f"setting {name} must be an integer, got {raw!r}") from exc


def _csv(environ: Mapping[str, str], name: str) -> frozenset[str]:
    raw = environ.get(name) or ""
    return frozenset(p.strip().lower() for p in raw.split(",") if p.strip())


def verify_tls_from_env(environ: Mapping[str, str] | None = None) -> bool:
    """TLS verification is on unless OKTA_VERIFY_TLS is explicitly false."""
    env = os.environ if environ is None else environ
    return (env.get("OKTA_VERIFY_TLS") or "true").strip().lower() not in _FALSE


@dataclass(frozen=True)
class Settings:
    auth_mode: str  # "oidc" or "none"
    secret_key: str
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    app_base_url: str
    allowed_emails: frozenset[str]
    allowed_domains: frozenset[str]
    default_env: str
    poll_interval_seconds: int
    buffer_size: int
    dedup_ring_size: int
    initial_lookback_minutes: int
    apps_refresh_seconds: int
    verify_tls: bool
    host: str
    port: int


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    mode = (env.get("AUTH_MODE") or "oidc").strip().lower()
    if mode not in ("oidc", "none"):
        raise SettingsError(f"setting AUTH_MODE must be 'oidc' or 'none', got {mode!r}")

    issuer = client_id = client_secret = base_url = ""
    allowed_emails: frozenset[str] = frozenset()
    allowed_domains: frozenset[str] = frozenset()
    secret = (env.get("FLASK_SECRET_KEY") or "").strip()
    if mode == "oidc":
        secret = _required(env, "FLASK_SECRET_KEY")
        issuer = _required(env, "OIDC_ISSUER").rstrip("/")
        client_id = _required(env, "OIDC_CLIENT_ID")
        client_secret = _required(env, "OIDC_CLIENT_SECRET")
        base_url = _required(env, "APP_BASE_URL").rstrip("/")
        allowed_emails = _csv(env, "OIDC_ALLOWED_EMAILS")
        allowed_domains = _csv(env, "OIDC_ALLOWED_DOMAINS")
        if not allowed_emails and not allowed_domains:
            raise SettingsError(
                "required setting OIDC_ALLOWED_EMAILS or OIDC_ALLOWED_DOMAINS is not set"
            )
    else:
        secret = secret or os.urandom(32).hex()
        base_url = (env.get("APP_BASE_URL") or "").strip().rstrip("/")

    return Settings(
        auth_mode=mode,
        secret_key=secret,
        oidc_issuer=issuer,
        oidc_client_id=client_id,
        oidc_client_secret=client_secret,
        app_base_url=base_url,
        allowed_emails=allowed_emails,
        allowed_domains=allowed_domains,
        default_env=(env.get("DEFAULT_ENV") or "").strip(),
        poll_interval_seconds=_int(env, "POLL_INTERVAL_SECONDS", 12),
        buffer_size=_int(env, "BUFFER_SIZE", 500),
        dedup_ring_size=_int(env, "DEDUP_RING_SIZE", 5000),
        initial_lookback_minutes=_int(env, "INITIAL_LOOKBACK_MINUTES", 5),
        apps_refresh_seconds=_int(env, "APPS_REFRESH_SECONDS", 1800),
        verify_tls=verify_tls_from_env(env),
        host=(env.get("HOST") or "127.0.0.1").strip(),
        port=_int(env, "PORT", 5005),
    )
