from datetime import datetime, timezone

import pytest
import requests
from conftest import FakeResponse, FakeSession

import app as app_module

ENV = next(iter(app_module.ENV_CONFIGS))
SINCE = datetime(2025, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    state = app_module._env_state[ENV]
    state["events"].clear()
    state["uuid_ring"].clear()
    state["uuid_set"].clear()
    state["raw_by_uuid"].clear()
    state["events_seen"] = 0
    monkeypatch.setattr(app_module.time, "sleep", lambda s: None)


def _use(monkeypatch, responses):
    sess = FakeSession(responses)
    monkeypatch.setattr(app_module, "okta_session", lambda env: sess)
    return sess


def test_normalize_user_sign_on_to_saml():
    ev = {
        "uuid": "u1",
        "eventType": "user.authentication.sso",
        "actor": {"type": "User", "id": "00u1", "alternateId": "a@example.test"},
        "target": [{"type": "AppInstance", "id": "0oa1", "displayName": "App One"}],
        "outcome": {"result": "SUCCESS"},
        "client": {"ipAddress": "192.0.2.1"},
        "debugContext": {"debugData": {"signOnMode": "SAML 2.0"}},
    }
    row = app_module._normalize_event(ev)
    assert row["sso_type"] == "SAML"
    assert row["user"] == "a@example.test"
    assert row["app"] == "App One"
    assert row["ip"] == "192.0.2.1"


def test_normalize_service_actor_uses_app_label_for_url_names():
    ev = {
        "eventType": "app.oauth2.token.grant",
        "actor": {"type": "PublicClientApp", "id": "0oa9", "displayName": "https://x.test/cb"},
        "target": [{"type": "User", "id": "00u2", "alternateId": "b@example.test"}],
    }
    apps = {"0oa9": {"label": "Friendly", "sso_type": "SAML"}}
    row = app_module._normalize_event(ev, apps)
    assert row["app"] == "Friendly"
    assert row["user"] == "b@example.test"
    assert row["sso_type"] == "SAML"


def test_normalize_empty_event_does_not_fail():
    row = app_module._normalize_event({})
    assert row["event_type"] == ""
    assert row["sso_type"] == ""


def test_matches_requires_every_token():
    ev = {"user": "Alice@example.test", "app": "Portal", "event_type": "x"}
    assert app_module._matches(ev, [])
    assert app_module._matches(ev, ["alice", "portal"])
    assert not app_module._matches(ev, ["alice", "missing"])


def test_ingest_deduplicates_by_uuid():
    raw = [{"uuid": "a"}, {"uuid": "b"}, {"uuid": "a"}, {"uuid": ""}]
    assert app_module._ingest(ENV, raw) == 2
    assert app_module._ingest(ENV, [{"uuid": "a"}]) == 0
    assert len(app_module._env_state[ENV]["events"]) == 2


def test_fetch_logs_follows_link_header_when_page_is_full(monkeypatch):
    page1 = [{"uuid": str(i)} for i in range(1000)]
    link = '<https://next.example.test/api/v1/logs?after=1>; rel="next"'
    sess = _use(
        monkeypatch,
        [FakeResponse(body=page1, headers={"Link": link}), FakeResponse(body=[{"uuid": "x"}])],
    )
    events, _ = app_module._fetch_logs(ENV, SINCE)
    assert len(events) == 1001
    assert sess.urls[1] == "https://next.example.test/api/v1/logs?after=1"


def test_fetch_logs_returns_partial_result_on_429(monkeypatch):
    _use(monkeypatch, [FakeResponse(status=429, headers={"Retry-After": "1"})])
    events, _ = app_module._fetch_logs(ENV, SINCE)
    assert events == []


def test_fetch_logs_http_error_keeps_status(monkeypatch):
    _use(monkeypatch, [FakeResponse(status=403)])
    with pytest.raises(requests.HTTPError) as info:
        app_module._fetch_logs(ENV, SINCE)
    assert app_module.error_summary(info.value) == "Okta HTTP error 403"


def test_error_summary_hides_exception_text():
    out = app_module.error_summary(RuntimeError("token abc123 leaked"))
    assert "abc123" not in out
    assert "RuntimeError" in out


def test_refresh_apps_maps_sign_on_modes(monkeypatch):
    body = [
        {"id": "1", "label": "One", "signOnMode": "SAML_2_0"},
        {"id": "2", "name": "two", "signOnMode": "OPENID_CONNECT"},
        {"id": "3", "label": "Three", "signOnMode": "BOOKMARK"},
    ]
    _use(monkeypatch, [FakeResponse(body=body)])
    assert app_module._refresh_apps(ENV) == 3
    apps = app_module._env_state[ENV]["apps_by_id"]
    assert [apps[k]["sso_type"] for k in "123"] == ["SAML", "OIDC", "OTHER"]
