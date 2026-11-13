# Okta Live Tail

A live, per-event view of the Okta System Log — for watching a specific sign-in land while
you debug it, across multiple Okta orgs (e.g. DEV / STG / PROD).

## What it does
- Polls `/api/v1/logs` on an interval (default 12 seconds) and keeps a rolling buffer of recent events per org.
- Type a substring (user, app name, app id, OAuth client id) to filter; failures and
  Okta-internal flows are shown, not hidden.
- Click any row for the raw event JSON.
- Read-only — nothing is written back to Okta.

**Type:** web service (Flask, gunicorn).

## Run
```bash
cp .env.example .env     # fill it in; AUTH_MODE=none is for local development only
pip install -e . && python app.py     # http://127.0.0.1:5005
```
Docker: `docker compose up` (reads `.env`, serves on port 8080, mounts `./config.yaml` as the
org list; edit that file or change the volume to use your own).

## Settings
All settings are environment variables (a `.env` file is read too); `.env.example` lists them
all. Required settings have no default and the app exits at startup naming the missing one.

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_MODE` | `oidc` | `none` turns the sign-in gate off (local development only) |
| `FLASK_SECRET_KEY` | required (oidc) | Session signing key |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | required (oidc) | Sign-in provider |
| `APP_BASE_URL` | required (oidc) | Public URL of this app |
| `OIDC_ALLOWED_EMAILS`, `OIDC_ALLOWED_DOMAINS` | one required (oidc) | Comma-separated allow-list |
| `LIVE_TAIL_CONFIG` | `config.yaml` | Org list (any number of orgs) |
| `DEFAULT_ENV` | `default_env` in config | Org shown first |
| `OKTA_LIVE_TAIL_<KEY>_AUTH_MODE` | `oauth` | `oauth` or `token`, per org |
| `OKTA_LIVE_TAIL_<KEY>_API_TOKEN` / `_PRIVATE_KEY` | none | Org credentials |
| `OKTA_ADMIN_<KEY>_API_TOKEN` | none | Admin token for `provision_app.py` / `bind_ro_admin.py` |
| `OKTA_VERIFY_TLS` | `true` | Set `false` only behind a TLS-inspecting proxy |
| `POLL_INTERVAL_SECONDS` | `12` | Poll interval |
| `BUFFER_SIZE` / `DEDUP_RING_SIZE` | `500` / `5000` | Events kept / UUIDs remembered per org |
| `INITIAL_LOOKBACK_MINUTES` / `APPS_REFRESH_SECONDS` | `5` / `1800` | Start-up lookback; app-label refresh |
| `HOST` / `PORT` | `127.0.0.1` / `5005` | Bind address (the image uses `0.0.0.0` and `8080`) |

Tests: `pip install -e ".[dev]" && pytest` (no network, Okta or LLM needed).

## Credentials
Two modes per org, chosen with `OKTA_LIVE_TAIL_<KEY>_AUTH_MODE`:
- **OAuth 2.0 client credentials with `private_key_jwt`** (preferred) — a service app holds a
  public key; the tool signs a short-lived assertion and receives a scoped `okta.logs.read`
  token. `provision_app.py` creates the service app and key pair; `bind_ro_admin.py` grants
  the read-only admin role that System Log access requires.
- **SSWS API token** — fallback, read from `OKTA_LIVE_TAIL_<KEY>_API_TOKEN` (or the OS keyring).

Credentials come from environment variables; the OS keyring is an optional fallback.

`provision_app.py` stores the new private key in the OS keyring by default, and exits before
calling Okta if none is usable. Without a keyring, pass `--key-out <new file>`: the key is
written there with mode 0600 (an existing file is never overwritten). Put its contents in
`OKTA_LIVE_TAIL_<KEY>_PRIVATE_KEY`, then delete the file.

## Stack
Python 3.10+ · Flask · gunicorn. A `Dockerfile` is included (runs one worker, port 8080).

## Known limitations
- **Pollers start on the first request** to each process, not at import.
- **No lockfile yet**; dependencies have version ranges in `pyproject.toml`.
- **`shared_*.py` modules** are still copies kept in this repository.
- **Polling edge cases:** events that publish out of order may be missed, and a rate-limited
  (HTTP 429) poll keeps only the pages fetched so far.
- **Scope mismatch in OAuth mode.** The tool requests `okta.logs.read` and
  `okta.apps.read`, but `provision_app.py` only grants `okta.logs.read` — grant
  `okta.apps.read` too, or the app-name refresh will fail.
- **In-memory only.** The event buffer (last 500 per org) is lost on restart; this is a
  live view, not a log store. The default poll interval is 12 seconds.
- **With `AUTH_MODE=none` the gate is off**, and `/login` grants a session automatically —
  local development only.
- **`provision_app.py` writes the real client ID into `config.yaml`.** Don't commit that
  file after provisioning.
