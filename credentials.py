from __future__ import annotations

from config import env_config
from shared_okta_auth import MissingCredentialError, from_env_or_keyring, load_pem

KEYRING_SERVICE = "okta-live-tail"


def client_id(env: str) -> str:
    cfg = env_config(env)
    cid = (cfg.get("client_id") or "").strip()
    if not cid:
        raise MissingCredentialError(
            f"no client_id for {env!r} in the org config file. Run:\n"
            f"  python provision_app.py --env {env}"
        )
    return cid


def private_key_pem(env: str) -> str:
    cfg = env_config(env)
    var = cfg.get("private_key_var") or f"OKTA_LIVE_TAIL_{env.upper()}_PRIVATE_KEY"
    v = load_pem(var, KEYRING_SERVICE)
    if v:
        return v
    raise MissingCredentialError(
        f"no private_key for {env!r}. Set the environment variable {var} "
        f"(PEM text, or base64 of it). Optionally store it in the OS keyring "
        f"under service {KEYRING_SERVICE!r}, account {var!r}."
    )


def admin_token(env: str) -> str:
    var = f"OKTA_ADMIN_{env.upper()}_API_TOKEN"
    v = from_env_or_keyring(var, "okta-app-admin")
    if v:
        return v
    raise MissingCredentialError(
        f"no admin token for {env!r}. Set the environment variable {var}, "
        f"or store it in the OS keyring under service 'okta-app-admin', account {var!r}."
    )


def has_credentials(env: str) -> bool:
    try:
        client_id(env)
        private_key_pem(env)
        return True
    except MissingCredentialError:
        return False
