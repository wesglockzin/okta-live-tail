#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging

from provision_app import _admin_sess
from config import load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s [%(levelname)s] %(message)s")
log = logging.getLogger("livetail.bind-ro-admin")


def _load_client_id(env: str) -> str:
    cfg = load_config()
    cid = cfg["envs"][env].get("client_id") or ""
    if not cid:
        raise SystemExit(f"config.yaml has no client_id for env={env}. Run provision_app.py --env {env} first.")
    return cid


def _ensure_ro_admin(sess, base: str, client_id: str) -> None:
    r = sess.get(f"{base}/oauth2/v1/clients/{client_id}/roles")
    r.raise_for_status()
    for role in r.json():
        if role.get("type") == "READ_ONLY_ADMIN":
            log.info("Read Only Admin already bound to OAuth client")
            return
    r = sess.post(f"{base}/oauth2/v1/clients/{client_id}/roles", json={"type": "READ_ONLY_ADMIN"})
    r.raise_for_status()
    log.info("bound Read Only Admin to OAuth client (binding id=%s)", r.json().get("id"))


def bind_env(env: str) -> None:
    sess, base = _admin_sess(env)
    client_id = _load_client_id(env)
    log.info("env=%s base=%s client_id=%s", env, base, client_id)
    _ensure_ro_admin(sess, base, client_id)
    log.info("done — env=%s RO Admin bound", env)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--env", required=True, choices=["dev", "stg", "prod"])
    args = p.parse_args()
    bind_env(args.env)


if __name__ == "__main__":
    main()
