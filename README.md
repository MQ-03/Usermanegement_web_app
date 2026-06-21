# User Management Web App

A Flask-based IT operations portal for managing user lifecycle across **on-premises Active Directory** and **Microsoft 365 / Entra ID**. It provides onboarding, offboarding, AD account and group management, M365 license assignment, and a full audit trail — behind Microsoft SSO (or a local admin fallback).

---

## Architecture

The system has two deployable components:

| Component | Runs on | Purpose |
|-----------|---------|---------|
| **Web app** (`app.py`) | Azure App Service (Linux, Python 3.13) | The portal UI + REST API. Talks to PostgreSQL, Microsoft Graph, and the AD agent. |
| **AD agent** (`ad_agent/app.py`) | On-premises, domain-joined Windows server / DC | A small API-key-secured REST service that runs PowerShell `ActiveDirectory` cmdlets. Lets the cloud app manage on-prem AD without a VPN. |

```
Browser ──► Azure App Service (app.py) ──► Azure Database for PostgreSQL (data)
                     │
                     ├──► Microsoft Graph  (Entra ID users, groups, licenses)
                     └──► AD Agent (on-prem) ──► Active Directory (PowerShell/RSAT)
```

Connectivity is shown live in the navbar: **Local-AD** (the agent) and **Entra-ID** (Graph) status dots.

---

## Features

- **Onboarding / offboarding** of users with a local record, on-prem AD account creation, group membership, and scheduled M365 license assignment (after directory sync).
- **AD management** — search, view, edit, enable/disable, delete users; manage groups and OUs; UPN-suffix management.
- **Microsoft 365 / Graph** — view subscribed SKUs and per-user licenses, assign/remove licenses, browse M365 groups and members.
- **Audit log** — every action recorded and attributed to the operator; CSV export. **Admin-only.**
- **Authentication** — Microsoft (Entra) SSO via MSAL, with an optional local admin login fallback. Access can be restricted by user list or group.
- **Org branding** — admins can upload a logo shown across the portal and on the login page.

---

## Tech stack

- **Backend:** Flask, gunicorn (prod), psycopg2 (PostgreSQL), MSAL (auth + Graph), requests
- **Frontend:** server-rendered Jinja templates + Bootstrap 5 (CDN), vanilla JS
- **Database:** Azure Database for PostgreSQL Flexible Server
- **AD agent:** Flask + waitress, PowerShell `ActiveDirectory` module (RSAT)

---

## Configuration

All configuration is via environment variables (App Settings on Azure; a local `.env` is auto-loaded in development).

### Web app

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL connection URI, e.g. `postgresql://user:pass@host:5432/db?sslmode=require`. **URL-encode special characters in the password** (`@`→`%40`, `$`→`%24`, `!`→`%21`, …). SSL (`sslmode=require`) is enforced automatically if not present. |
| `SECRET_KEY` | ✅ (prod) | Fixed random hex for signing sessions. If unset, a random key is generated per start (sessions reset on every restart). |
| `DATA_DIR` | — | Persistent dir for the uploaded logo. On Azure set to `/home/data` so it survives restarts/deploys. |
| `SESSION_COOKIE_SECURE` | — | `true` in production (HTTPS). |
| **Microsoft SSO (login)** | | |
| `AUTH_TENANT_ID` | for SSO | Entra tenant ID (falls back to `GRAPH_TENANT_ID`). |
| `AUTH_CLIENT_ID` | for SSO | App registration client ID (falls back to `GRAPH_CLIENT_ID`). |
| `AUTH_CLIENT_SECRET` | for SSO | App registration client secret (falls back to `GRAPH_CLIENT_SECRET`). |
| `AUTH_REDIRECT_URI` | for SSO | e.g. `https://<app>.azurewebsites.net/auth/callback`. Must be registered under the app's **Authentication → Redirect URIs**. |
| **Access control** | | |
| `ALLOWED_USERS` | — | Comma-separated UPNs allowed to sign in. |
| `ALLOWED_GROUP_ID` | — | Entra group ID; only members may sign in. |
| `ADMIN_USERS` | — | Comma-separated UPNs granted admin (audit log, branding, sensitive ops). |
| `ADMIN_GROUP_ID` | — | Entra group ID whose members are admins. |
| **Local admin fallback** | | |
| `ADMIN_USERNAME` | — | Local admin username (default `admin`). |
| `ADMIN_PASSWORD_HASH` | — | Werkzeug password hash (preferred). |
| `ADMIN_PASSWORD` | — | Plain password fallback (use the hash instead where possible). |
| **Microsoft Graph (app-only)** | | |
| `GRAPH_TENANT_ID` | for Graph | Tenant ID. |
| `GRAPH_CLIENT_ID` | for Graph | App registration client ID (needs Graph application permissions + admin consent). |
| `GRAPH_CLIENT_SECRET` | for Graph | Client secret. |
| `DEFAULT_USAGE_LOCATION` | — | Default 2-letter ISO country for license assignment (e.g. `GB`). |
| **AD agent client** | | |
| `AD_AGENT_URL` | for AD | Base URL of the on-prem agent, e.g. `https://10.0.0.5:5001`. |
| `AD_AGENT_KEY` | for AD | Must match the agent's `AGENT_API_KEY`. |

### AD agent (`ad_agent/`)

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENT_API_KEY` | ✅ | Shared secret; must match the web app's `AD_AGENT_KEY`. |
| `AGENT_PORT` | — | Listen port (default `5001`). |
| `AD_USERS_OU` | — | Default OU DN for new users. |
| `ADSYNC_ENABLED` | — | `true` to trigger an Entra Connect delta sync after creating a user. |
| `ADSYNC_SERVER` | — | Remote Entra Connect server (WinRM); blank = run locally. |

---

## Local development

```bash
python3 -m venv umenv
source umenv/bin/activate          # Windows: umenv\Scripts\activate
pip install -r requirements.txt

# Create a .env with at least DATABASE_URL and SECRET_KEY (see Configuration)
python app.py                      # serves on http://localhost:5050
```

You need a reachable PostgreSQL instance — point `DATABASE_URL` at a local Postgres or your Azure Flexible Server (with your client IP allowed in its firewall). Tables are created automatically on startup (`init_db()`).

---

## Database

- The app uses **PostgreSQL** via psycopg2. Schema is created and migrated idempotently at startup.
- SSL is required for Azure PostgreSQL Flexible Server; the app adds `sslmode=require` automatically when it isn't already in `DATABASE_URL`.
- Tables: `users`, `audit_log`, `scheduled_tasks`, `ad_disabled_groups`, `settings`.

---

## Deployment (Azure App Service)

Deployment is automated via GitHub Actions (`.github/workflows/azure-webapps-python.yml`) on push to `main`. The workflow stages `app.py`, `ad_manager.py`, `graph_manager.py`, `requirements.txt`, and `templates/`, then publishes to the App Service.

On the App Service, set the environment variables above under **Settings → Environment variables → App settings**, then **Apply** (restarts the app). App Service auto-detects Flask and runs `gunicorn app:app`.

Recommended:
- `DATA_DIR=/home/data` so the uploaded logo persists.
- A fixed `SECRET_KEY`.
- Allow the App Service outbound IPs in the PostgreSQL firewall.

---

## AD agent setup (on-premises)

Run on a domain-joined Windows server with the RSAT `ActiveDirectory` PowerShell module installed:

```powershell
cd ad_agent
python -m venv venv; .\venv\Scripts\activate
pip install -r requirements.txt
# Set AGENT_API_KEY (and optionally AD_USERS_OU, ADSYNC_*) in ad_agent/.env
python app.py        # waitress in production; see install_service.ps1 to run as a service
```

Point the web app's `AD_AGENT_URL`/`AD_AGENT_KEY` at this agent. The agent's `/health` endpoint is unauthenticated for liveness checks; all `/ad/*` routes require the `X-API-Key` header.

---

## Security notes

- Audit log and org-branding endpoints require admin (`ADMIN_USERS` or `ADMIN_GROUP_ID`).
- Keep `AGENT_API_KEY` / `AD_AGENT_KEY` secret and prefer HTTPS for the agent.
- Client secrets (Graph/SSO) expire — rotate before expiry to avoid sudden disconnects.
- The uploaded logo excludes SVG to avoid script-in-SVG XSS.
