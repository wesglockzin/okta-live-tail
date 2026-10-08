from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_ROOT = Path(__file__).parent
_CONFIG = _ROOT / "config.yaml"


@lru_cache(maxsize=1)
def load_config() -> dict:
    with _CONFIG.open() as f:
        return yaml.safe_load(f)


def env_config(env: str) -> dict:
    envs = load_config()["envs"]
    if env not in envs:
        raise KeyError(f"unknown env: {env!r} (known: {sorted(envs)})")
    return envs[env]


def known_envs() -> list[str]:
    return list(load_config()["envs"].keys())


def default_env() -> str:
    return load_config().get("default_env", "dev")
