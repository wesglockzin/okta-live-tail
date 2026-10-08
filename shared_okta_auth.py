from __future__ import annotations

import base64
import logging
import os
import secrets
import threading
import time
from typing import Callable

__version__ = "1.0.0"

_DEFAULT_LOG = logging.getLogger("shared_okta_auth")

REFRESH_LEEWAY_SEC = 300
ASSERTION_TTL_SEC = 60

try:
    import keyring as _keyring
except ImportError:
    _keyring = None


class MissingCredentialError(RuntimeError):
    pass


def from_env_or_keyring(var_name: str, keyring_service: str) -> str:
    v = (os.environ.get(var_name) or "").strip()
    if v:
        return v
    if _keyring:
        try:
            v = (_keyring.get_password(keyring_service, var_name) or "").strip()
            if v:
                return v
        except Exception:
            pass
    return ""


def normalize_pem(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return s
    if "BEGIN" not in s:
        try:
            s = base64.b64decode(s).decode()
        except Exception:
            pass
    if "\\n" in s and "\n" not in s:
        s = s.replace("\\n", "\n")
    return s


def load_pem(var_name: str, keyring_service: str) -> str:
    return normalize_pem(from_env_or_keyring(var_name, keyring_service))


def mount_retries(session, total: int = 4, backoff_factor: float = 0.5) -> None:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    retry = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)


class OAuthClientCredentials:

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        scopes: str,
        client_id: str | Callable[[], str],
        private_key_pem: str | Callable[[], str],
        verify: bool = False,
        timeout: int = 20,
        refresh_leeway_sec: int = REFRESH_LEEWAY_SEC,
        assertion_ttl_sec: int = ASSERTION_TTL_SEC,
        logger: logging.Logger | None = None,
    ):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.scopes = scopes
        self._client_id = client_id
        self._private_key_pem = private_key_pem
        self._verify = verify
        self._timeout = timeout
        self._leeway = refresh_leeway_sec
        self._assertion_ttl = assertion_ttl_sec
        self._log = logger or _DEFAULT_LOG
        self._lock = threading.Lock()
        self._cached: tuple[str, float] | None = None

    def _resolve(self, v: str | Callable[[], str], what: str) -> str:
        s = (v() if callable(v) else v) or ""
        s = s.strip()
        if not s:
            raise MissingCredentialError(f"[{self.name}] no {what} available")
        return s

    def _build_assertion(self, token_endpoint: str) -> str:
        import jwt
        cid = self._resolve(self._client_id, "client_id")
        now = int(time.time())
        claims = {
            "iss": cid,
            "sub": cid,
            "aud": token_endpoint,
            "iat": now,
            "exp": now + self._assertion_ttl,
            "jti": secrets.token_urlsafe(24),
        }
        pem = normalize_pem(self._resolve(self._private_key_pem, "private key PEM"))
        return jwt.encode(claims, pem, algorithm="RS256")

    def _mint(self) -> tuple[str, float]:
        import requests
        token_endpoint = f"{self.base_url}/oauth2/v1/token"
        assertion = self._build_assertion(token_endpoint)
        resp = requests.post(
            token_endpoint,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "client_credentials",
                "scope": self.scopes,
                "client_assertion_type":
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            },
            timeout=self._timeout,
            verify=self._verify,
        )
        if not resp.ok:
            raise RuntimeError(
                f"client_credentials (private_key_jwt) mint failed for "
                f"{self.name}: HTTP {resp.status_code}: {resp.text[:400]}"
            )
        body = resp.json()
        access = body.get("access_token") or ""
        if not access:
            raise RuntimeError(
                f"[{self.name}] mint succeeded but no access_token in body: {body}")
        expires_in = int(body.get("expires_in") or 3600)
        self._log.info("[%s] minted OAuth access token (expires_in=%ds)",
                       self.name, expires_in)
        return access, time.time() + expires_in

    def access_token(self, force: bool = False) -> str:
        now = time.time()
        cached = self._cached
        if not force and cached and (cached[1] - now) > self._leeway:
            return cached[0]
        with self._lock:
            cached = self._cached
            if not force and cached and (cached[1] - now) > self._leeway:
                return cached[0]
            self._cached = self._mint()
            return self._cached[0]

    def invalidate(self) -> None:
        with self._lock:
            self._cached = None
