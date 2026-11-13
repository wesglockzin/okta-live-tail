import pytest

from settings import SettingsError, load_settings, verify_tls_from_env

FULL = {
    "FLASK_SECRET_KEY": "test-key-not-real",  # pragma: allowlist secret
    "OIDC_ISSUER": "https://idp.example.test/",
    "OIDC_CLIENT_ID": "client-not-real",
    "OIDC_CLIENT_SECRET": "test-secret-not-real",  # pragma: allowlist secret
    "APP_BASE_URL": "https://tail.example.test/",
    "OIDC_ALLOWED_DOMAINS": "Allowed.test",
}


def test_empty_environment_refuses_to_start():
    with pytest.raises(SettingsError, match="FLASK_SECRET_KEY"):
        load_settings({})


@pytest.mark.parametrize(
    "missing",
    ["FLASK_SECRET_KEY", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "APP_BASE_URL"],
)
def test_each_required_setting_is_named(missing):
    env = {k: v for k, v in FULL.items() if k != missing}
    with pytest.raises(SettingsError, match=missing):
        load_settings(env)


def test_allow_list_is_required():
    env = {k: v for k, v in FULL.items() if k != "OIDC_ALLOWED_DOMAINS"}
    with pytest.raises(SettingsError, match="OIDC_ALLOWED"):
        load_settings(env)


def test_full_oidc_settings():
    s = load_settings(FULL)
    assert s.auth_mode == "oidc"
    assert s.oidc_issuer == "https://idp.example.test"
    assert s.app_base_url == "https://tail.example.test"
    assert s.allowed_domains == {"allowed.test"}
    assert s.host == "127.0.0.1"


def test_auth_mode_none_needs_nothing():
    s = load_settings({"AUTH_MODE": "none"})
    assert s.auth_mode == "none"
    assert s.secret_key


def test_bad_auth_mode_and_bad_int():
    with pytest.raises(SettingsError, match="AUTH_MODE"):
        load_settings({"AUTH_MODE": "maybe"})
    with pytest.raises(SettingsError, match="PORT"):
        load_settings({"AUTH_MODE": "none", "PORT": "abc"})


def test_tls_verification_defaults_on():
    assert verify_tls_from_env({}) is True
    assert verify_tls_from_env({"OKTA_VERIFY_TLS": "false"}) is False
    assert load_settings({"AUTH_MODE": "none"}).verify_tls is True
