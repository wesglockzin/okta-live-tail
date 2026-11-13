import os
import stat
import sys

import keyring
import pytest
import yaml
from keyring.backends import fail, null

import provision_app


@pytest.fixture
def calls(monkeypatch):
    """Replace every Okta-facing step with a recorder; no HTTP happens."""
    rec = []

    def admin_sess(env):
        rec.append("admin_sess")
        return object(), "https://okta.example.test"

    monkeypatch.setattr(provision_app, "_admin_sess", admin_sess)
    monkeypatch.setattr(provision_app, "find_existing_app", lambda *a: None)
    monkeypatch.setattr(
        provision_app, "create_service_app", lambda *a: {"id": "0oa1", "credentials": {}}
    )
    monkeypatch.setattr(provision_app, "grant_scopes", lambda *a: [])
    monkeypatch.setattr(provision_app, "_gen_rsa_keypair", lambda: ("PEM-NOT-REAL", {"kid": "k1"}))
    monkeypatch.setattr(
        provision_app, "update_config_with_client_id", lambda *a: rec.append("config")
    )
    return rec


def _run(monkeypatch, *args):
    env = provision_app.known_envs()[0]
    monkeypatch.setattr(sys, "argv", ["provision_app", "--env", env, *args])
    provision_app.main()


@pytest.mark.parametrize("backend", [fail.Keyring, null.Keyring])
def test_unusable_keyring_exits_before_any_okta_call(monkeypatch, calls, backend):
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend())
    with pytest.raises(SystemExit):
        _run(monkeypatch)
    assert calls == []


def test_dry_run_skips_keyring_check(monkeypatch, calls):
    monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())
    _run(monkeypatch, "--dry-run")
    assert calls == ["admin_sess"]


def test_config_not_written_when_key_storage_fails(monkeypatch, calls):
    monkeypatch.setattr(provision_app, "require_usable_keyring", lambda: None)

    def boom(env, pem):
        raise RuntimeError("keyring locked")

    monkeypatch.setattr(provision_app, "stash_pem_to_keychain", boom)
    with pytest.raises(RuntimeError):
        _run(monkeypatch)
    assert "config" not in calls


def test_key_out_works_without_keyring(monkeypatch, calls, tmp_path):
    monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())
    out = tmp_path / "key.pem"
    _run(monkeypatch, "--key-out", str(out))
    assert out.read_text() == "PEM-NOT-REAL"
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert calls == ["admin_sess", "config"]


def test_key_out_refuses_existing_file_before_okta(monkeypatch, calls, tmp_path):
    out = tmp_path / "key.pem"
    out.write_text("keep")
    with pytest.raises(SystemExit):
        _run(monkeypatch, "--key-out", str(out))
    assert calls == []
    assert out.read_text() == "keep"


def test_key_out_in_missing_directory_exits_before_okta(monkeypatch, calls, tmp_path):
    out = tmp_path / "no-such-dir" / "key.pem"
    with pytest.raises(SystemExit):
        _run(monkeypatch, "--key-out", str(out))
    assert calls == []


def test_key_out_placeholder_removed_when_okta_step_fails(monkeypatch, calls, tmp_path):
    def boom(*a):
        raise RuntimeError("okta down")

    monkeypatch.setattr(provision_app, "create_service_app", boom)
    out = tmp_path / "key.pem"
    with pytest.raises(RuntimeError):
        _run(monkeypatch, "--key-out", str(out))
    assert not out.exists()


def test_original_error_survives_when_key_file_vanished(monkeypatch, calls, tmp_path):
    out = tmp_path / "key.pem"

    def boom(*a):
        out.unlink()
        raise RuntimeError("okta down")

    monkeypatch.setattr(provision_app, "create_service_app", boom)
    with pytest.raises(RuntimeError, match="okta down"):
        _run(monkeypatch, "--key-out", str(out))


def test_written_key_is_kept_and_fd_not_closed_twice(monkeypatch, calls, tmp_path):
    def boom(*a):
        raise RuntimeError("config read-only")

    closed = []
    real_close = os.close
    monkeypatch.setattr(provision_app, "update_config_with_client_id", boom)
    monkeypatch.setattr(provision_app.os, "close", lambda fd: (closed.append(fd), real_close(fd)))
    out = tmp_path / "key.pem"
    with pytest.raises(RuntimeError, match="config read-only"):
        _run(monkeypatch, "--key-out", str(out))
    assert out.read_text() == "PEM-NOT-REAL"
    assert closed == []


def test_update_config_writes_to_live_tail_config(monkeypatch, tmp_path):
    path = tmp_path / "orgs.yaml"
    path.write_text("envs:\n  one:\n    url: https://okta.example.test\n")
    monkeypatch.setenv("LIVE_TAIL_CONFIG", str(path))
    provision_app.update_config_with_client_id("one", "My App", "client-1")
    block = yaml.safe_load(path.read_text())["envs"]["one"]
    assert block["client_id"] == "client-1"
    assert block["private_key_var"] == "OKTA_LIVE_TAIL_ONE_PRIVATE_KEY"  # pragma: allowlist secret
