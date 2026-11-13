from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

_DEFAULT_CONFIG = Path(__file__).parent / "config.yaml"


def config_path() -> Path:
    """Org list location: LIVE_TAIL_CONFIG, else config.yaml next to the code."""
    override = (os.environ.get("LIVE_TAIL_CONFIG") or "").strip()
    return Path(override) if override else _DEFAULT_CONFIG


@lru_cache(maxsize=1)
def load_config() -> dict:
    with config_path().open() as f:
        return yaml.safe_load(f)


def env_config(env: str) -> dict:
    envs = load_config()["envs"]
    if env not in envs:
        raise KeyError(f"unknown env: {env!r} (known: {sorted(envs)})")
    return envs[env]


def known_envs() -> list[str]:
    return list(load_config()["envs"].keys())


def default_env() -> str:
    return load_config().get("default_env") or known_envs()[0]
