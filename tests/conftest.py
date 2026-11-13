import os

import pytest

# Set before `app` is imported: the app reads its settings at import time.
os.environ["AUTH_MODE"] = "none"
os.environ["FLASK_SECRET_KEY"] = "test-key-not-real"  # pragma: allowlist secret
os.environ.pop("LIVE_TAIL_CONFIG", None)

import app as app_module  # noqa: E402


@pytest.fixture(autouse=True)
def _no_background_workers(monkeypatch):
    monkeypatch.setattr(app_module, "start_workers", lambda: None)


@pytest.fixture
def client():
    return app_module.app.test_client()


@pytest.fixture
def oidc_settings(monkeypatch):
    """Switch the running app to OIDC mode with an allow-list."""
    import dataclasses

    s = dataclasses.replace(
        app_module.settings,
        auth_mode="oidc",
        allowed_emails=frozenset({"ok@example.test"}),
        allowed_domains=frozenset({"allowed.test"}),
    )
    monkeypatch.setattr(app_module, "settings", s)
    return s


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body if body is not None else []
        self.headers = headers or {}
        self.text = str(self._body)

    def json(self):
        return self._body

    def raise_for_status(self):
        import requests

        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """Replays queued responses and records the requested URLs."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []

    def get(self, url, params=None, timeout=None):
        self.urls.append(url)
        return self.responses.pop(0)
