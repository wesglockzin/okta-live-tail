# Okta Live Tail

A live, per-event view of the Okta System Log — for watching a specific sign-in land while
you debug it, across multiple Okta orgs (e.g. DEV / STG / PROD).

## What it does
- Polls `/api/v1/logs` every few seconds and keeps a rolling buffer of recent events per org.
- Type a substring (user, app name, app id, OAuth client id) to filter; failures and
  Okta-internal flows are shown, not hidden.
- Click any row for the raw event JSON.
- Read-only — nothing is written back to Okta.

## Run locally
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python app.py              # http://127.0.0.1:5005
```

## Credentials
Two modes per org, chosen in `config.yaml`:
- **OAuth 2.0 client credentials with `private_key_jwt`** (preferred) — a service app holds a
  public key; the tool signs a short-lived assertion and receives a scoped `okta.logs.read`
  token. `provision_app.py` creates the service app and key pair; `bind_ro_admin.py` grants
  the read-only admin role that System Log access requires.
- **SSWS API token** — fallback, read from the OS keyring or `OKTA_LIVE_TAIL_<ENV>_API_TOKEN`.

Optional OIDC sign-in gate: set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`APP_BASE_URL` and `FLASK_SECRET_KEY`; when absent the gate is off (local development only).

## Stack
Python 3 · Flask · gunicorn. A `Dockerfile` is included (port 8080).
