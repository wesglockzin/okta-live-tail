from __future__ import annotations

import logging
import threading

from config import env_config
from credentials import client_id, private_key_pem
from shared_okta_auth import OAuthClientCredentials

log = logging.getLogger("live-tail.oauth")

DEFAULT_SCOPES = "okta.logs.read okta.apps.read"

_sources: dict[str, OAuthClientCredentials] = {}
_lock = threading.Lock()


def _source(env: str) -> OAuthClientCredentials:
    src = _sources.get(env)
    if src is None:
        with _lock:
            src = _sources.get(env)
            if src is None:
                src = OAuthClientCredentials(
                    name=f"okta-live-tail/{env}",
                    base_url=env_config(env)["url"],
                    scopes=DEFAULT_SCOPES,
                    client_id=lambda e=env: client_id(e),
                    private_key_pem=lambda e=env: private_key_pem(e),
                    logger=log,
                )
                _sources[env] = src
    return src


def access_token(env: str) -> str:
    return _source(env).access_token()


def invalidate(env: str) -> None:
    _source(env).invalidate()
