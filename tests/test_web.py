import pytest

import app as app_module


@pytest.mark.parametrize(
    "value",
    [
        "//evil.test",
        "//evil.test/x",
        "https://evil.test",
        "/\\evil.test",
        "evil",
        "",
        None,
        "/a\nb",
    ],
)
def test_safe_next_rejects_offsite_targets(value):
    assert app_module.safe_next(value) == "/"


@pytest.mark.parametrize("value", ["/", "/api/events?env=dev", "/howto"])
def test_safe_next_keeps_local_paths(value):
    assert app_module.safe_next(value) == value


def test_is_authorized(oidc_settings):
    assert app_module.is_authorized("ok@example.test")
    assert app_module.is_authorized("Anyone@Allowed.test")
    assert not app_module.is_authorized("other@example.test")
    assert not app_module.is_authorized("nobody")
    assert not app_module.is_authorized(None)


def test_health_is_open_without_auth(client, oidc_settings):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_gate_blocks_api_without_session(client, oidc_settings):
    r = client.get("/api/events")
    assert r.status_code == 401


def test_gate_redirects_pages_to_login(client, oidc_settings):
    r = client.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_gate_allows_signed_in_session(client, oidc_settings):
    with client.session_transaction() as sess:
        sess["user"] = {"email": "ok@example.test"}
    assert client.get("/api/events").status_code == 200


def test_gate_rejects_session_of_person_not_on_allow_list(client, oidc_settings):
    with client.session_transaction() as sess:
        sess["user"] = {"email": "other@example.test"}
    assert client.get("/api/events").status_code == 401
    with client.session_transaction() as sess:
        assert "user" not in sess


class _FakeOidc:
    def __init__(self, userinfo):
        self.userinfo = userinfo

    def authorize_access_token(self):
        return {"userinfo": self.userinfo}


@pytest.mark.parametrize(
    ("userinfo", "status"),
    [
        ({"email": "other@example.test"}, 403),
        ({"email": "ok@example.test", "email_verified": False}, 403),
        ({"email": "ok@example.test", "email_verified": True}, 302),
        ({"email": "ok@example.test"}, 302),
    ],
)
def test_oidc_callback_enforces_allow_list(client, oidc_settings, monkeypatch, userinfo, status):
    monkeypatch.setattr(app_module.oauth, "oidc", _FakeOidc(userinfo), raising=False)
    r = client.get("/oidc/callback")
    assert r.status_code == status
    with client.session_transaction() as sess:
        assert ("user" in sess) == (status == 302)


def test_auth_mode_none_leaves_routes_open(client):
    assert client.get("/api/events").status_code == 200


def test_unknown_env_is_rejected(client):
    assert client.get("/api/events?env=nope").status_code == 400
    assert client.get("/api/events/raw/abc?env=nope").status_code == 400


def test_raw_event_lookup(client):
    env = next(iter(app_module.ENV_CONFIGS))
    app_module._env_state[env]["raw_by_uuid"]["u-1"] = {"uuid": "u-1"}
    assert client.get(f"/api/events/raw/u-1?env={env}").get_json() == {"uuid": "u-1"}
    assert client.get(f"/api/events/raw/missing?env={env}").status_code == 404
