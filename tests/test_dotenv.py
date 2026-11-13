import importlib
from pathlib import Path

import dotenv

import config


def test_config_loads_env_file_next_to_code(monkeypatch):
    """Importing config must read .env, so provision_app and bind_ro_admin see it."""
    calls = []
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: calls.append(a))
    try:
        importlib.reload(config)
    finally:
        monkeypatch.undo()
        importlib.reload(config)
    assert calls == [(Path(config.__file__).parent / ".env",)]
