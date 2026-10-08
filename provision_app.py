from __future__ import annotations

import argparse
import json
import logging
import os
import sys

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from config import env_config, known_envs

log = logging.getLogger("livetail.provision")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
)

KEYRING_SERVICE = "okta-live-tail"

DEFAULT_SCOPES = [
    "okta.logs.read",
]


def _admin_token(env: str) -> str:
    import keyring
    var = {"dev": "OKTA_ADMIN_DEV_API_TOKEN",
           "stg": "OKTA_ADMIN_STG_API_TOKEN",
           "prod": "OKTA_ADMIN_PROD_API_TOKEN"}[env]
    v = keyring.get_password("okta-app-admin", var) or os.environ.get(var, "")
    if not v:
        sys.exit(f"no admin token for {env} (Keychain okta-app-admin / {var}).")
    return v.strip()


def _admin_sess(env: str) -> tuple[requests.Session, str]:
    cfg = env_config(env)
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({
        "Authorization": f"SSWS {_admin_token(env)}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    return sess, cfg["url"].rstrip("/")


def _gen_rsa_keypair() -> tuple[str, dict]:
    import hashlib

    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    pub_numbers = key.public_key().public_numbers()

    def _b64(n: int) -> str:
        import base64
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    kid = hashlib.sha256(pub_numbers.n.to_bytes(256, "big")).hexdigest()[:16]
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64(pub_numbers.n),
        "e": _b64(pub_numbers.e),
    }
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return pem, jwk


def find_existing_app(sess: requests.Session, base: str, app_name: str) -> dict | None:
    r = sess.get(f"{base}/api/v1/apps",
                 params={"q": app_name, "limit": 50})
    r.raise_for_status()
    for app in r.json():
        if app.get("label") == app_name:
            return app
    return None


def create_service_app(sess: requests.Session, base: str, app_name: str,
                       jwk: dict) -> dict:
    payload = {
        "name": "oidc_client",
        "label": app_name,
        "signOnMode": "OPENID_CONNECT",
        "credentials": {
            "oauthClient": {
                "token_endpoint_auth_method": "private_key_jwt",
            },
        },
        "settings": {
            "oauthClient": {
                "application_type": "service",
                "grant_types": ["client_credentials"],
                "response_types": ["token"],
                "redirect_uris": [],
                "post_logout_redirect_uris": [],
                "jwks": {"keys": [jwk]},
            },
        },
    }
    r = sess.post(f"{base}/api/v1/apps", json=payload)
    if not r.ok:
        sys.exit(f"app create failed: HTTP {r.status_code}: {r.text[:500]}")
    app = r.json()
    log.info("created service app %s (id=%s, kid=%s)", app_name, app.get("id"), jwk["kid"])
    return app


def update_app_jwks(sess: requests.Session, base: str, app: dict, jwk: dict) -> dict:
    payload = json.loads(json.dumps(app))
    for k in ("_links", "_embedded", "lastUpdated", "created"):
        payload.pop(k, None)
    creds = payload.setdefault("credentials", {}).setdefault("oauthClient", {})
    creds["token_endpoint_auth_method"] = "private_key_jwt"
    creds.pop("client_secret", None)
    settings = payload.setdefault("settings", {}).setdefault("oauthClient", {})
    settings["jwks"] = {"keys": [jwk]}

    r = sess.put(f"{base}/api/v1/apps/{app['id']}", json=payload)
    if not r.ok:
        sys.exit(f"app JWKS update failed: HTTP {r.status_code}: {r.text[:500]}")
    log.info("updated app %s — auth=private_key_jwt, kid=%s", app["id"], jwk["kid"])
    return r.json()


def grant_scopes(sess: requests.Session, base: str, app_id: str,
                 scopes: list[str]) -> list[str]:
    granted = []
    for scope in scopes:
        payload = {"scopeId": scope, "issuer": base}
        r = sess.post(f"{base}/api/v1/apps/{app_id}/grants", json=payload)
        if r.ok:
            granted.append(scope)
            log.info("granted %s", scope)
        elif r.status_code in (400, 409) and any(
                s in r.text.lower() for s in
                ("exists", "duplicate", "already been", "already granted")):
            granted.append(scope)
            log.info("scope %s already granted (idempotent)", scope)
        else:
            log.warning("grant %s failed: HTTP %s: %s", scope, r.status_code, r.text[:200])
    return granted


def stash_pem_to_keychain(env: str, pem: str) -> str:
    import keyring
    var = f"OKTA_LIVE_TAIL_{env.upper()}_PRIVATE_KEY"
    keyring.set_password(KEYRING_SERVICE, var, pem)
    log.info("stored private key in Keychain %s / %s (value not echoed)",
             KEYRING_SERVICE, var)
    return var


def update_config_with_client_id(env: str, app_name: str, client_id: str) -> None:
    import yaml
    from pathlib import Path
    cfg_path = Path(__file__).parent / "config.yaml"
    text = cfg_path.read_text()
    data = yaml.safe_load(text) or {}
    block = data.setdefault("envs", {}).setdefault(env, {})
    block["client_id"] = client_id
    block["private_key_var"] = f"OKTA_LIVE_TAIL_{env.upper()}_PRIVATE_KEY"
    block.setdefault("app_name", app_name)
    cfg_path.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    log.info("wrote client_id + private_key_var to config.yaml for env=%s", env)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--env", choices=known_envs(), required=True)
    p.add_argument("--app-name", default="Okta Live Tail")
    p.add_argument("--scopes", nargs="+", default=DEFAULT_SCOPES)
    p.add_argument("--rotate-key", action="store_true",
                   help="Generate a new keypair, update the app's JWKS, restash the PEM.")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    sess, base = _admin_sess(args.env)
    log.info("env=%s base=%s app_name=%s scopes=%s",
             args.env, base, args.app_name, args.scopes)

    existing = find_existing_app(sess, base, args.app_name)

    if args.dry_run:
        action = "create" if not existing else ("rotate-key" if args.rotate_key else "upgrade-to-jwk")
        log.info("[dry-run] would %s for %s", action, args.app_name)
        return

    pem, jwk = _gen_rsa_keypair()

    if existing:
        app = update_app_jwks(sess, base, existing, jwk)
        action = "rotated-key" if args.rotate_key else "upgraded"
    else:
        app = create_service_app(sess, base, args.app_name, jwk)
        action = "created"

    grant_scopes(sess, base, app["id"], args.scopes)
    client_id = (app.get("credentials", {}).get("oauthClient", {}).get("client_id")
                 or app["id"])
    update_config_with_client_id(args.env, args.app_name, client_id)
    var = stash_pem_to_keychain(args.env, pem)
    pem = None

    print(f"\n=== {action.upper()} ===")
    print(f"  app_id          : {app['id']}")
    print(f"  client_id       : {client_id}")
    print(f"  kid (public JWK): {jwk['kid']}")
    print(f"  private key     : stored in Keychain {KEYRING_SERVICE} / {var} (NOT echoed)")
    print(f"  scopes granted  : {', '.join(args.scopes)}")


if __name__ == "__main__":
    main()
