from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import msal
import psycopg2
import psycopg2.extras
from flask import (Flask, Response, g, has_request_context, jsonify, redirect,
                   render_template, request, send_from_directory, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from ad_manager import ADManager
    _ad: ADManager | None = ADManager()
except Exception:
    _ad = None

try:
    from graph_manager import GraphManager
    _graph: GraphManager | None = GraphManager()
except Exception:
    _graph = None

APP_DIR = Path(__file__).resolve().parent
# Persistent data lives under DATA_DIR (set DATA_DIR=/home/data on Azure App Service
# so the DB and uploaded logo survive restarts and deployments). Defaults to the app
# directory for local development.
DATA_DIR = Path(os.getenv("DATA_DIR", str(APP_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# PostgreSQL connection string (Azure Database for PostgreSQL Flexible Server).
# e.g. postgresql://user:pass@server.postgres.database.azure.com:5432/dbname?sslmode=require
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Org-standard logo (uploaded in Settings, shown to all users), served via /branding.
BRANDING_DIR     = DATA_DIR / "branding"
# SVG is intentionally excluded (script-in-SVG XSS risk when served same-origin).
ALLOWED_LOGO_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

# When a freshly-created user's M365 license is assigned. Rather than waiting a
# fixed, conservative window, the worker makes a first attempt after a short
# delay and then retries on a readiness check (does the account exist in Entra
# yet?) until it appears — so the license lands as soon as AD delta sync
# propagates the account, instead of failing once and giving up.
SYNC_DELAY_MINUTES       = int(os.getenv("SYNC_DELAY_MINUTES", "10"))   # first attempt
LICENSE_RETRY_MINUTES    = int(os.getenv("LICENSE_RETRY_MINUTES", "5")) # gap between retries
LICENSE_MAX_WAIT_MINUTES = int(os.getenv("LICENSE_MAX_WAIT_MINUTES", "180"))  # give up after

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload cap
# Trust the App Service / reverse-proxy headers so https is detected correctly.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=true in production (HTTPS).
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
)

# ── Authentication ────────────────────────────────────────────────────────────────
# Session secret: set SECRET_KEY in .env to keep sessions valid across restarts.
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(hours=8)

# Local password fallback (used only when Entra SSO is not configured).
ADMIN_USERNAME      = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
ADMIN_PASSWORD      = os.getenv("ADMIN_PASSWORD", "")

# Entra (Azure AD) SSO — falls back to the Graph app registration if dedicated
# AUTH_* vars are not set. Requires a Web redirect URI registered in the app.
AUTH_TENANT_ID     = os.getenv("AUTH_TENANT_ID")     or os.getenv("GRAPH_TENANT_ID", "")
AUTH_CLIENT_ID     = os.getenv("AUTH_CLIENT_ID")     or os.getenv("GRAPH_CLIENT_ID", "")
AUTH_CLIENT_SECRET = os.getenv("AUTH_CLIENT_SECRET") or os.getenv("GRAPH_CLIENT_SECRET", "")
AUTH_REDIRECT_URI  = os.getenv("AUTH_REDIRECT_URI", "http://localhost:5050/auth/callback")
AUTH_SCOPES        = ["User.Read"]
ALLOWED_USERS      = [u.strip().lower() for u in os.getenv("ALLOWED_USERS", "").split(",") if u.strip()]
ALLOWED_GROUP_ID   = os.getenv("ALLOWED_GROUP_ID", "").strip()
# SSO accounts with admin rights (the local ADMIN_USERNAME login is always admin).
ADMIN_USERS        = [u.strip().lower() for u in os.getenv("ADMIN_USERS", "").split(",") if u.strip()]
# Entra group whose members are treated as admins (privileged actions).
ADMIN_GROUP_ID     = os.getenv("ADMIN_GROUP_ID", "").strip()
SSO_ENABLED        = bool(AUTH_TENANT_ID and AUTH_CLIENT_ID and AUTH_CLIENT_SECRET)
# Local admin login: always on when SSO is off; when SSO is on, only if credentials
# are configured (acts as a break-glass admin alongside SSO).
LOCAL_LOGIN_ENABLED = (not SSO_ENABLED) or bool(ADMIN_PASSWORD_HASH or ADMIN_PASSWORD)

# Endpoints reachable without a session.
_PUBLIC_ENDPOINTS = {"login", "logout", "auth_login", "auth_callback", "static", "branding_file"}
# Endpoints exempt from CSRF (auth boundary / pre-session).
_CSRF_EXEMPT      = {"login", "logout", "auth_login", "auth_callback", "static"}
_CSRF_METHODS     = {"POST", "PUT", "PATCH", "DELETE"}


def _auth_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        AUTH_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{AUTH_TENANT_ID}",
        client_credential=AUTH_CLIENT_SECRET,
    )


def _check_credentials(username: str, password: str) -> bool:
    if not (username and password):
        return False
    if not secrets.compare_digest(username, ADMIN_USERNAME):
        return False
    if ADMIN_PASSWORD_HASH:
        return check_password_hash(ADMIN_PASSWORD_HASH, password)
    if ADMIN_PASSWORD:
        return secrets.compare_digest(password, ADMIN_PASSWORD)
    # Nothing configured — default only when SSO is also unavailable (prevents lockout).
    if not SSO_ENABLED:
        return secrets.compare_digest(password, "admin")
    return False


def _safe_next(value: str) -> str:
    return value if (value.startswith("/") and not value.startswith("//")) else ""


def _is_admin(user: str, claims: dict) -> bool:
    """Admin if listed in ADMIN_USERS or a member of ADMIN_GROUP_ID."""
    if user and user.lower() in ADMIN_USERS:
        return True
    if ADMIN_GROUP_ID and _graph is not None:
        oid = claims.get("oid", "")
        try:
            return bool(oid) and _graph.user_in_group(oid, ADMIN_GROUP_ID)
        except Exception:
            return False
    return False


def _authorize_user(user: str, claims: dict) -> str:
    """Return '' if the signed-in user may use the app, else an error message.
    Applies the optional ALLOWED_USERS list and ALLOWED_GROUP_ID membership check."""
    if ALLOWED_USERS and user.lower() not in ALLOWED_USERS:
        return f"{user} is not authorised to use this app."
    if ALLOWED_GROUP_ID:
        if _graph is None:
            return "Group authorisation is unavailable (Graph not configured)."
        oid = claims.get("oid", "")
        try:
            if not oid or not _graph.user_in_group(oid, ALLOWED_GROUP_ID):
                return f"{user} is not a member of the required group."
        except Exception as exc:
            return f"Could not verify group membership: {str(exc)[:150]}"
    return ""


@app.before_request
def _security() -> Any:
    # 1. Authentication
    if request.endpoint not in _PUBLIC_ENDPOINTS and not session.get("user"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login", next=request.path))
    # Ensure a CSRF token exists for any authenticated session.
    if session.get("user") and "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    # 2. CSRF — validate header on state-changing requests.
    if request.method in _CSRF_METHODS and request.endpoint not in _CSRF_EXEMPT:
        token = session.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, request.headers.get("X-CSRF-Token", "")):
            return jsonify({"error": "CSRF token missing or invalid"}), 400
    return None


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if session.get("user"):
        return redirect(url_for("index"))
    nxt = _safe_next(request.args.get("next", ""))
    if request.method == "POST":
        if not LOCAL_LOGIN_ENABLED:
            return render_template("login.html", sso=SSO_ENABLED, local=False, next=nxt,
                                   error="Password login is disabled."), 403
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if _check_credentials(username, password):
            session.permanent = True
            session["user"] = username
            session["name"] = username
            session["is_admin"] = True   # local admin login is always admin
            log_audit("login", username, "Signed in (local admin)")
            return redirect(nxt or url_for("index"))
        return render_template("login.html", sso=SSO_ENABLED, local=True, next=nxt,
                               error="Invalid username or password"), 401
    return render_template("login.html", sso=SSO_ENABLED, local=LOCAL_LOGIN_ENABLED, next=nxt)


@app.route("/auth/login")
def auth_login() -> Any:
    if not SSO_ENABLED:
        return redirect(url_for("login"))
    session["oauth_state"] = secrets.token_urlsafe(24)
    session["oauth_nonce"] = secrets.token_urlsafe(24)
    session["post_login"]  = _safe_next(request.args.get("next", ""))
    url = _auth_app().get_authorization_request_url(
        AUTH_SCOPES,
        state=session["oauth_state"],
        nonce=session["oauth_nonce"],
        redirect_uri=AUTH_REDIRECT_URI,
        prompt="select_account",
    )
    return redirect(url)


@app.route("/auth/callback")
def auth_callback() -> Any:
    if "error" in request.args:
        desc = request.args.get("error_description", request.args.get("error", "Login failed"))
        return render_template("login.html", sso=True, error=desc[:200]), 400
    if not request.args.get("state") or request.args.get("state") != session.get("oauth_state"):
        return render_template("login.html", sso=True, error="Invalid login state — please try again."), 400
    code = request.args.get("code")
    if not code:
        return redirect(url_for("login"))
    result = _auth_app().acquire_token_by_authorization_code(
        code, scopes=AUTH_SCOPES, redirect_uri=AUTH_REDIRECT_URI,
        nonce=session.get("oauth_nonce"),
    )
    if "id_token_claims" not in result:
        desc = result.get("error_description", "Authentication failed")
        return render_template("login.html", sso=True, error=desc[:200]), 401
    claims = result["id_token_claims"]
    user   = (claims.get("preferred_username") or claims.get("email") or claims.get("name", "")).strip()
    authz_error = _authorize_user(user, claims)
    if authz_error:
        return render_template("login.html", sso=True, error=authz_error), 403
    for k in ("oauth_state", "oauth_nonce"):
        session.pop(k, None)
    session.permanent = True
    session["user"] = user
    session["name"] = claims.get("name", user)
    session["is_admin"] = _is_admin(user, claims)
    log_audit("login", user, "Signed in via Microsoft SSO")
    return redirect(session.pop("post_login", "") or url_for("index"))


@app.route("/logout")
def logout() -> Any:
    if session.get("user"):
        log_audit("logout", session.get("user"), "Signed out")
    session.clear()
    return redirect(url_for("login"))


# ── PostgreSQL helpers ────────────────────────────────────────────────────────
# Raise this for a duplicate-key / constraint violation, replacing
# sqlite3.IntegrityError throughout the app.
IntegrityError = psycopg2.IntegrityError


class PGConnection:
    """Thin sqlite3-compatible adapter over a psycopg2 connection so the existing
    call sites keep working unchanged:
      • ``conn.execute(sql, params)`` translates ``?`` placeholders to ``%s`` and
        returns a cursor (rows are RealDictRow, so ``row["col"]`` and ``dict(row)``
        behave like sqlite3.Row).
      • ``commit()/rollback()/close()`` pass through to the underlying connection.
    """

    def __init__(self, conn: "psycopg2.extensions.connection") -> None:
        self._conn = conn

    def execute(self, sql: str, params: Any = ()) -> "psycopg2.extras.RealDictCursor":
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql.replace("?", "%s"), params)
        return cur

    def executescript(self, sql: str) -> None:
        # psycopg2 executes multiple ';'-separated statements in a single call,
        # standing in for sqlite3's executescript().
        self._conn.cursor().execute(sql)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()


def _connect() -> PGConnection:
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    # Azure PostgreSQL Flexible Server requires TLS; force it unless the caller
    # already specified an sslmode in the connection string.
    kwargs: dict[str, Any] = {}
    if "sslmode=" not in DATABASE_URL:
        kwargs["sslmode"] = "require"
    return PGConnection(psycopg2.connect(DATABASE_URL, **kwargs))


def get_db() -> PGConnection:
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = _connect()
    return db


@app.teardown_appcontext
def close_db(exc: Any) -> None:
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db() -> None:
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id                SERIAL PRIMARY KEY,
                full_name         TEXT NOT NULL,
                upn               TEXT UNIQUE NOT NULL,
                department        TEXT DEFAULT '',
                job_title         TEXT DEFAULT '',
                manager           TEXT DEFAULT '',
                location          TEXT DEFAULT '',
                license           TEXT DEFAULT '',
                start_date        TEXT DEFAULT '',
                end_date          TEXT DEFAULT '',
                ticket            TEXT DEFAULT '',
                reason            TEXT DEFAULT '',
                notes             TEXT DEFAULT '',
                status            TEXT NOT NULL DEFAULT 'active',
                created_at        TEXT NOT NULL,
                updated_at        TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER,
                full_name   TEXT NOT NULL,
                action      TEXT NOT NULL,
                details     TEXT DEFAULT '',
                ticket      TEXT DEFAULT '',
                actor       TEXT DEFAULT '',
                timestamp   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id           SERIAL PRIMARY KEY,
                task_type    TEXT NOT NULL,
                upn          TEXT NOT NULL,
                payload      TEXT DEFAULT '',
                run_at       TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'pending',
                result       TEXT DEFAULT '',
                created_at   TEXT NOT NULL,
                completed_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS ad_disabled_groups (
                upn         TEXT PRIMARY KEY,
                groups_json TEXT NOT NULL DEFAULT '[]',
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS offboarded_licenses (
                upn        TEXT PRIMARY KEY,
                skus_json  TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT DEFAULT ''
            );
        """)
        # Migration: add newer columns to pre-existing databases. Postgres supports
        # ADD COLUMN IF NOT EXISTS, so this is idempotent without introspection.
        new_cols = [
            ("phone",             "TEXT DEFAULT ''"),
            ("mobile",            "TEXT DEFAULT ''"),
            ("country",           "TEXT DEFAULT ''"),
            ("description",       "TEXT DEFAULT ''"),
            ("contract_end_date", "TEXT DEFAULT ''"),
        ]
        for col_name, col_def in new_cols:
            db.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col_name} {col_def}")
        db.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor TEXT DEFAULT ''")
        db.commit()


def now_utc() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def current_actor() -> str:
    """The logged-in operator performing the action; 'system' outside a request."""
    if has_request_context():
        return session.get("name") or session.get("user") or "system"
    return "system"


def log_audit(action: str, target: str = "", details: str = "", ticket: str = "") -> None:
    """Record any portal action in the audit log, attributed to the current operator."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, full_name, action, details, ticket, actor, timestamp)"
            " VALUES (?,?,?,?,?,?,?)",
            (None, target or "—", action, details, ticket, current_actor(), now_utc()),
        )
        db.commit()
    except Exception:
        # A failed statement aborts the Postgres transaction; roll back so the
        # rest of the request can keep using the same connection.
        try:
            get_db().rollback()
        except Exception:
            pass


# AD-edit field -> local users column. Mirrors AD edits to the local record.
_AD_TO_LOCAL = {
    "display_name": "full_name", "department": "department", "title": "job_title",
    "manager": "manager", "phone": "phone", "mobile": "mobile",
    "country": "country", "description": "description",
}


def sync_local_from_ad(upn: str, data: dict, db: Any = None) -> None:
    """Update the local users record (matched by current UPN) to reflect an AD edit.
    Pass `db` to run outside a request (e.g. the scheduler thread)."""
    db  = db or get_db()
    row = db.execute("SELECT id FROM users WHERE LOWER(upn)=LOWER(?)", (upn,)).fetchone()
    if not row:
        return
    sets: list[str] = []
    params: list[Any] = []
    for key, col in _AD_TO_LOCAL.items():
        if key not in data:
            continue
        val = str(data[key]).strip()
        if col == "full_name" and not val:
            continue  # never blank the display name
        sets.append(f"{col}=?")
        params.append(val)
    if data.get("new_upn"):
        sets.append("upn=?")
        params.append(str(data["new_upn"]).strip().lower())
    if not sets:
        return
    sets.append("updated_at=?")
    params.append(now_utc())
    params.append(row["id"])
    db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", params)
    db.commit()


def get_setting(key: str, default: str = "") -> str:
    row = get_db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?,?)"
        " ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
        (key, value),
    )
    db.commit()


def logo_url() -> str:
    """Public URL of the org logo (with a cache-busting version), or '' if unset."""
    fname = get_setting("logo_file", "")
    if not fname:
        return ""
    # The filename is stored in the (persistent) DB, but the file itself lives on
    # disk. After a deploy/restart the file can be gone (e.g. DATA_DIR not on
    # persistent storage) — fall back to the default icon instead of a broken image.
    if not (BRANDING_DIR / fname).is_file():
        return ""
    ver = get_setting("logo_updated", "")
    url = url_for("branding_file", filename=fname)
    return f"{url}?v={ver}" if ver else url


@app.route("/branding/<path:filename>")
def branding_file(filename: str) -> Any:
    """Serve the uploaded org logo from the persistent data directory."""
    return send_from_directory(str(BRANDING_DIR), filename)


@app.context_processor
def _inject_branding() -> dict:
    try:
        return {"logo_url": logo_url()}
    except Exception:
        return {"logo_url": ""}


_COUNTRY_CODES = {
    "india": "IN", "united kingdom": "GB", "uk": "GB", "great britain": "GB", "england": "GB",
    "united states": "US", "usa": "US", "united states of america": "US", "america": "US",
    "canada": "CA", "australia": "AU", "germany": "DE", "france": "FR", "spain": "ES",
    "italy": "IT", "netherlands": "NL", "ireland": "IE", "singapore": "SG", "japan": "JP",
    "china": "CN", "brazil": "BR", "mexico": "MX", "south africa": "ZA", "new zealand": "NZ",
    "switzerland": "CH", "sweden": "SE", "norway": "NO", "denmark": "DK", "finland": "FI",
    "poland": "PL", "portugal": "PT", "belgium": "BE", "austria": "AT", "philippines": "PH",
    "malaysia": "MY", "indonesia": "ID", "sri lanka": "LK", "bangladesh": "BD",
    "pakistan": "PK", "nepal": "NP", "united arab emirates": "AE", "uae": "AE", "saudi arabia": "SA",
}


def usage_location_for(upn: str, db: PGConnection) -> str:
    """A 2-letter ISO usageLocation is required before assigning an M365 license.
    Resolve from the user's Country (code or name), then DEFAULT_USAGE_LOCATION."""
    row = db.execute("SELECT country FROM users WHERE LOWER(upn)=LOWER(?)", (upn,)).fetchone()
    raw = ((row["country"] if row and row["country"] else "") or "").strip()
    if len(raw) == 2 and raw.isalpha():
        return raw.upper()
    mapped = _COUNTRY_CODES.get(raw.lower())
    if mapped:
        return mapped
    default = os.getenv("DEFAULT_USAGE_LOCATION", "").strip().upper()
    return default if (len(default) == 2 and default.isalpha()) else ""


# ── Pages ───────────────────────────────────────────────────────────────────────

@app.route("/")
def index() -> Any:
    return render_template("index.html",
                           csrf_token=session.get("csrf_token", ""),
                           current_user=session.get("name") or session.get("user", ""),
                           is_admin=session.get("is_admin", False),
                           logo_url=logo_url())


# ── Settings (org branding) ───────────────────────────────────────────────────

@app.route("/api/settings")
def get_settings() -> Any:
    return jsonify({"logo_url": logo_url()})


@app.route("/api/settings/logo", methods=["POST"])
def upload_logo() -> Any:
    if not session.get("is_admin"):
        return jsonify({"error": "Admin privileges required"}), 403
    f = request.files.get("logo")
    if not f or not f.filename:
        return jsonify({"error": "No file uploaded"}), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_LOGO_EXT:
        return jsonify({"error": "Unsupported type. Use PNG, JPG, GIF, or WEBP."}), 400
    BRANDING_DIR.mkdir(parents=True, exist_ok=True)
    for old in BRANDING_DIR.glob("logo.*"):       # drop any previous logo
        try:
            old.unlink()
        except OSError:
            pass
    fname = f"logo{ext}"
    f.save(str(BRANDING_DIR / fname))
    set_setting("logo_file", fname)
    set_setting("logo_updated", datetime.utcnow().strftime("%Y%m%d%H%M%S"))
    log_audit("logo_updated", "branding", f"Organization logo updated ({fname})")
    return jsonify({"message": "Logo updated", "logo_url": logo_url()})


@app.route("/api/settings/logo", methods=["DELETE"])
def delete_logo() -> Any:
    if not session.get("is_admin"):
        return jsonify({"error": "Admin privileges required"}), 403
    for old in BRANDING_DIR.glob("logo.*"):
        try:
            old.unlink()
        except OSError:
            pass
    set_setting("logo_file", "")
    log_audit("logo_removed", "branding", "Organization logo removed")
    return jsonify({"message": "Logo removed"})


# ── Stats ───────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def stats() -> Any:
    db = get_db()
    # RealDictCursor rows are dict-like, so read the COUNT(*) by its column alias.
    total      = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    active     = db.execute("SELECT COUNT(*) AS n FROM users WHERE status='active'").fetchone()["n"]
    offboarded = db.execute("SELECT COUNT(*) AS n FROM users WHERE status='offboarded'").fetchone()["n"]
    # created_at is stored as 'YYYY-MM-DD HH:MM:SS' text, so compare against a
    # Python-computed cutoff (date('now',...) is SQLite-only and absent in Postgres).
    cutoff = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    recent = db.execute(
        "SELECT COUNT(*) AS n FROM users WHERE status='active' AND created_at >= ?",
        (cutoff,),
    ).fetchone()["n"]
    return jsonify({"total": total, "active": active, "offboarded": offboarded, "recent": recent})


# ── Local Users ─────────────────────────────────────────────────────────────────

@app.route("/api/users")
def list_users() -> Any:
    status = request.args.get("status", "all")
    q      = request.args.get("q", "").strip().lower()
    db     = get_db()
    sql    = "SELECT * FROM users"
    params: list[Any] = []
    conditions: list[str] = []
    if status != "all":
        conditions.append("status = ?")
        params.append(status)
    if q:
        conditions.append("(LOWER(full_name) LIKE ? OR LOWER(upn) LIKE ? OR LOWER(department) LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY LOWER(full_name)"
    rows = db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users/<int:uid>")
def get_user(uid: int) -> Any:
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))


@app.route("/api/users", methods=["POST"])
def onboard_user() -> Any:
    data      = request.get_json(force=True) or {}
    full_name = data.get("full_name", "").strip()
    upn       = data.get("upn", "").strip().lower()
    if not full_name:
        return jsonify({"error": "Full name is required"}), 400
    if not upn:
        return jsonify({"error": "UPN is required"}), 400
    db  = get_db()
    ts  = now_utc()
    try:
        cur = db.execute(
            """
            INSERT INTO users
              (full_name, upn, department, job_title, manager, location,
               license, start_date, notes, phone, mobile, country,
               description, contract_end_date, status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?)
            RETURNING id
            """,
            (
                full_name, upn,
                data.get("department", ""),
                data.get("job_title", ""),
                data.get("manager", ""),
                data.get("location", ""),
                data.get("license", ""),
                data.get("start_date", ""),
                data.get("notes", ""),
                data.get("phone", ""),
                data.get("mobile", ""),
                data.get("country", ""),
                data.get("description", ""),
                data.get("contract_end_date", ""),
                ts, ts,
            ),
        )
        uid = cur.fetchone()["id"]
        db.execute(
            "INSERT INTO audit_log (user_id, full_name, action, details, ticket, actor, timestamp) VALUES (?,?,?,?,?,?,?)",
            (uid, full_name, "onboarded", f"Onboarded: {upn}", data.get("ticket", ""), current_actor(), ts),
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        return jsonify({"error": f"A user with UPN '{upn}' already exists"}), 409
    return jsonify({"id": uid, "message": f"{full_name} has been onboarded"}), 201


@app.route("/api/users/<int:uid>/offboard", methods=["POST"])
def offboard_user(uid: int) -> Any:
    data     = request.get_json(force=True) or {}
    end_date = data.get("end_date", "").strip()
    ticket   = data.get("ticket", "").strip()
    if not end_date:
        return jsonify({"error": "End date is required"}), 400
    if not ticket:
        return jsonify({"error": "Ticket number is required"}), 400
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user["status"] == "offboarded":
        return jsonify({"error": "User is already offboarded"}), 400
    ts = now_utc()
    db.execute(
        """
        UPDATE users
           SET status='offboarded', end_date=?, ticket=?, reason=?,
               notes=?, updated_at=?
         WHERE id=?
        """,
        (end_date, ticket, data.get("reason", ""),
         data.get("notes", user["notes"] or ""), ts, uid),
    )
    db.execute(
        "INSERT INTO audit_log (user_id, full_name, action, details, ticket, actor, timestamp) VALUES (?,?,?,?,?,?,?)",
        (uid, user["full_name"], "offboarded",
         f"Offboarded. Reason: {data.get('reason', 'Not specified')}", ticket, current_actor(), ts),
    )
    db.commit()
    return jsonify({"message": f"{user['full_name']} has been offboarded"})


@app.route("/api/users/<int:uid>/reactivate", methods=["POST"])
def reactivate_user(uid: int) -> Any:
    """Move an offboarded local record back to active (re-enable / re-onboard)."""
    data     = request.get_json(silent=True) or {}
    reassign = data.get("reassign_licenses", True)
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user["status"] == "active":
        return jsonify({"error": "User is already active"}), 400
    ts  = now_utc()
    upn = user["upn"] or ""
    db.execute(
        """
        UPDATE users
           SET status='active', end_date=NULL, updated_at=?
         WHERE id=?
        """,
        (ts, uid),
    )
    db.execute(
        "INSERT INTO audit_log (user_id, full_name, action, details, ticket, actor, timestamp) VALUES (?,?,?,?,?,?,?)",
        (uid, user["full_name"], "ad_enabled",
         "Reactivated — moved back to active users", user["ticket"] or "", current_actor(), ts),
    )

    # Re-assign the M365 licenses that were removed at offboarding.
    assigned, failed = [], []
    row  = db.execute("SELECT skus_json FROM offboarded_licenses WHERE upn=?", (upn,)).fetchone()
    skus = json.loads(row["skus_json"]) if row else []
    if reassign and skus and _graph is not None and upn:
        loc = usage_location_for(upn, db)
        if loc:
            try:
                _graph.set_usage_location(upn, loc)
            except Exception:
                pass
        for sku in skus:
            try:
                _graph.assign_license(upn, sku)
                assigned.append(sku)
            except Exception:
                failed.append(sku)
        db.execute("DELETE FROM offboarded_licenses WHERE upn=?", (upn,))
    db.commit()
    if assigned:
        log_audit("license_assigned", upn, f"Re-assigned {len(assigned)} license(s) on re-enable")

    msg = f"{user['full_name']} has been reactivated"
    if assigned:
        msg += f" — {len(assigned)} license(s) re-assigned"
    if failed:
        msg += f" ({len(failed)} license(s) could not be re-assigned — assign manually)"
    return jsonify({"message": msg, "licenses_assigned": len(assigned), "licenses_failed": len(failed)})


@app.route("/api/users/<int:uid>", methods=["DELETE"])
def delete_user(uid: int) -> Any:
    db   = get_db()
    user = db.execute("SELECT full_name FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.execute(
        "INSERT INTO audit_log (user_id, full_name, action, details, actor, timestamp) VALUES (?,?,?,?,?,?)",
        (uid, user["full_name"], "deleted", "User record permanently deleted", current_actor(), now_utc()),
    )
    db.commit()
    return jsonify({"message": f"{user['full_name']} deleted"})


# ── Audit ───────────────────────────────────────────────────────────────────────

@app.route("/api/audit")
def audit_log() -> Any:
    if not session.get("is_admin"):
        return jsonify({"error": "Admin privileges required"}), 403
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/audit/export")
def export_audit() -> Any:
    """Download the full audit log as CSV."""
    if not session.get("is_admin"):
        return jsonify({"error": "Admin privileges required"}), 403
    rows = get_db().execute(
        "SELECT timestamp, actor, action, full_name, details, ticket"
        " FROM audit_log ORDER BY timestamp DESC"
    ).fetchall()
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["Timestamp (UTC)", "Performed By", "Action", "Target", "Details", "Ticket"])
    for r in rows:
        w.writerow([r["timestamp"], r["actor"], r["action"], r["full_name"], r["details"], r["ticket"]])
    log_audit("audit_exported", "audit_log", f"Exported {len(rows)} audit entries")
    fname = "audit_log_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S") + ".csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ── AD — Connectivity ───────────────────────────────────────────────────────────

@app.route("/api/ad/status")
def ad_status() -> Any:
    if _ad is None:
        return jsonify({"connected": False, "error": "AD manager unavailable"})
    return jsonify(_ad.status())


# ── AD — Users ──────────────────────────────────────────────────────────────────

@app.route("/api/ad/users")
def ad_list_users() -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    try:
        return jsonify(_ad.search_users(request.args.get("q", "")))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/ad/users/<string:upn>")
def ad_get_user(upn: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    user = _ad.get_user(upn)
    if not user:
        return jsonify({"error": "User not found in AD"}), 404
    return jsonify(user)


@app.route("/api/ad/users", methods=["POST"])
def ad_create_user() -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    data = request.get_json(force=True) or {}
    required = ("full_name", "upn", "sam", "given_name", "surname", "password")
    missing = [f for f in required if not data.get(f, "").strip()]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400
    try:
        res = _ad.create_user(
            full_name=data["full_name"].strip(),
            upn=data["upn"].strip(),
            sam=data["sam"].strip(),
            display_name=data.get("display_name", ""),
            given_name=data["given_name"].strip(),
            surname=data["surname"].strip(),
            password=data["password"],
            department=data.get("department", ""),
            title=data.get("title", ""),
            manager=data.get("manager", ""),
            ou=data.get("ou", ""),
            must_change_password=bool(data.get("must_change_password", True)),
            phone=data.get("phone", ""),
            mobile=data.get("mobile", ""),
            country=data.get("country", ""),
            description=data.get("description", ""),
            contract_end_date=data.get("contract_end_date", ""),
            email=data.get("email", ""),
            ad_groups=data.get("ad_groups", []),
        )
        sync = (res or {}).get("delta_sync", "unknown")
        log_audit("ad_created", data["upn"].strip(),
                  f"AD account created (SAM {data['sam'].strip()}); delta sync: {sync}")
        return jsonify({"message": f"AD account created for {data['upn']}", "delta_sync": sync}), 201
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ad/ous")
def ad_list_ous() -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    try:
        return jsonify(_ad.get_ous())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/ad/upn-suffixes")
def ad_list_upn_suffixes() -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    try:
        return jsonify(_ad.get_upn_suffixes())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/ad/upn-suffixes", methods=["POST"])
def ad_add_upn_suffix() -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    if not session.get("is_admin"):
        return jsonify({"error": "Admin privileges required"}), 403
    data   = request.get_json(force=True) or {}
    suffix = data.get("suffix", "").strip().lstrip("@").lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", suffix):
        return jsonify({"error": "Enter a valid domain, e.g. tryzens.com"}), 400
    try:
        _ad.add_upn_suffix(suffix)
        log_audit("upn_suffix_added", suffix, f"UPN suffix '{suffix}' added to forest")
        return jsonify({"message": f"UPN suffix '{suffix}' added"})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ad/upn-suffixes/<string:suffix>", methods=["DELETE"])
def ad_remove_upn_suffix(suffix: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    if not session.get("is_admin"):
        return jsonify({"error": "Admin privileges required"}), 403
    try:
        _ad.remove_upn_suffix(suffix)
        log_audit("upn_suffix_removed", suffix, f"UPN suffix '{suffix}' removed from forest")
        return jsonify({"message": f"UPN suffix '{suffix}' removed"})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ad/users/<string:upn>", methods=["PUT"])
def ad_update_user(upn: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    data = request.get_json(force=True) or {}
    # Changing the UPN (suffix) is an admin-only action.
    if data.get("new_upn") and not session.get("is_admin"):
        data.pop("new_upn", None)
    try:
        _ad.update_user(upn, data)
        sync_local_from_ad(upn, data)   # reflect the change in the local Active list
        changed = ", ".join(sorted(k for k in data)) or "—"
        new_upn = data.get("new_upn")
        log_audit("ad_updated", new_upn or upn,
                  f"Updated {upn} (fields: {changed})" + (f"; UPN → {new_upn}" if new_upn else ""))
        return jsonify({"message": f"AD account updated for {upn}"})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ad/users/<string:upn>", methods=["DELETE"])
def ad_delete_user(upn: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    if not session.get("is_admin"):
        return jsonify({"error": "Admin privileges required to delete AD users"}), 403
    try:
        _ad.delete_user(upn)
        log_audit("ad_deleted", upn, "AD account permanently deleted")
        return jsonify({"message": f"AD account deleted for {upn}"})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ad/users/<string:upn>/disable", methods=["POST"])
def ad_disable_user(upn: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    try:
        result = _ad.disable_user(upn)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400
    removed = result.get("removed_groups", []) if isinstance(result, dict) else []
    if removed:
        # Remember the groups so a later enable can restore them.
        db = get_db()
        db.execute(
            "INSERT INTO ad_disabled_groups (upn, groups_json, updated_at) VALUES (?,?,?)"
            " ON CONFLICT (upn) DO UPDATE SET"
            " groups_json=EXCLUDED.groups_json, updated_at=EXCLUDED.updated_at",
            (upn, json.dumps(removed), now_utc()),
        )
        db.commit()
    log_audit("ad_disabled", upn, f"AD account disabled; removed from {len(removed)} group(s)")
    return jsonify({"message": f"AD account disabled for {upn}", "removed_groups": len(removed)})


@app.route("/api/ad/users/<string:upn>/enable", methods=["POST"])
def ad_enable_user(upn: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    db  = get_db()
    row = db.execute("SELECT groups_json FROM ad_disabled_groups WHERE upn=?", (upn,)).fetchone()
    restore = json.loads(row["groups_json"]) if row else []
    try:
        _ad.enable_user(upn, restore_groups=restore)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400
    if row:
        db.execute("DELETE FROM ad_disabled_groups WHERE upn=?", (upn,))
        db.commit()
    msg = f"AD account enabled for {upn}"
    if restore:
        msg += f" — restored {len(restore)} group(s)"
    log_audit("ad_enabled", upn, f"AD account enabled; restored {len(restore)} group(s)")
    return jsonify({"message": msg})


# ── AD — Groups ─────────────────────────────────────────────────────────────────

@app.route("/api/ad/groups")
def ad_list_groups() -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    try:
        return jsonify(_ad.search_groups(request.args.get("q", "")))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/ad/groups/<string:sam>/members")
def ad_group_members(sam: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    try:
        return jsonify(_ad.get_group_members(sam))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/ad/groups/<string:sam>/members", methods=["POST"])
def ad_add_to_group(sam: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    data = request.get_json(force=True) or {}
    user_sam = data.get("user_sam", "").strip()
    if not user_sam:
        return jsonify({"error": "user_sam is required"}), 400
    try:
        _ad.add_to_group(sam, user_sam)
        log_audit("ad_group_add", user_sam, f"Added to AD group {sam}")
        return jsonify({"message": f"{user_sam} added to {sam}"})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ad/groups/<string:sam>/members/<string:user_sam>", methods=["DELETE"])
def ad_remove_from_group(sam: str, user_sam: str) -> Any:
    if _ad is None:
        return jsonify({"error": "AD manager unavailable"}), 503
    try:
        _ad.remove_from_group(sam, user_sam)
        log_audit("ad_group_remove", user_sam, f"Removed from AD group {sam}")
        return jsonify({"message": f"{user_sam} removed from {sam}"})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


# ── Graph — Connectivity ────────────────────────────────────────────────────────

@app.route("/api/graph/status")
def graph_status() -> Any:
    if _graph is None:
        return jsonify({"connected": False, "error": "Graph manager unavailable"})
    return jsonify(_graph.status())


# ── Graph — Licenses ────────────────────────────────────────────────────────────

@app.route("/api/graph/licenses")
def graph_licenses() -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    try:
        return jsonify(_graph.get_licenses())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/users/<string:upn>/licenses")
def graph_user_licenses(upn: str) -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    try:
        return jsonify(_graph.get_user_licenses(upn))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/users/<string:upn>/sync")
def graph_user_sync(upn: str) -> Any:
    """Entra ID presence / on-prem sync status for an active user."""
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    try:
        return jsonify(_graph.get_sync_status(upn))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/users/<string:upn>/licenses", methods=["POST"])
def graph_assign_license(upn: str) -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    data   = request.get_json(force=True) or {}
    sku_id = data.get("sku_id", "").strip()
    if not sku_id:
        return jsonify({"error": "sku_id is required"}), 400
    try:
        loc = usage_location_for(upn, get_db())
        if loc:
            _graph.set_usage_location(upn, loc)
        _graph.assign_license(upn, sku_id)
        log_audit("license_assigned", upn, f"M365 license {sku_id} assigned")
        return jsonify({"message": f"License assigned to {upn}"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/schedule-license", methods=["POST"])
def schedule_license() -> Any:
    """Queue an M365 license assignment to run after SYNC_DELAY_MINUTES."""
    data   = request.get_json(force=True) or {}
    upn    = data.get("upn", "").strip()
    sku_id = data.get("sku_id", "").strip()
    if not upn or not sku_id:
        return jsonify({"error": "upn and sku_id are required"}), 400
    now    = datetime.utcnow()
    ts     = now.strftime("%Y-%m-%d %H:%M:%S")
    run_at = (now + timedelta(minutes=SYNC_DELAY_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute(
        "INSERT INTO scheduled_tasks (task_type, upn, payload, run_at, status, created_at)"
        " VALUES ('assign_license', ?, ?, ?, 'pending', ?)",
        (upn, sku_id, run_at, ts),
    )
    db.execute(
        "INSERT INTO audit_log (user_id, full_name, action, details, actor, timestamp) VALUES (?,?,?,?,?,?)",
        (None, upn, "license_scheduled",
         f"License assignment queued for {run_at} UTC (in {SYNC_DELAY_MINUTES} min)", current_actor(), ts),
    )
    db.commit()
    return jsonify({"message": f"License assignment scheduled for {run_at} UTC", "run_at": run_at})


# ── Generic scheduling ──────────────────────────────────────────────────────────

_SCHED_TYPES = {"create_user", "edit_ad_user", "offboard_user", "enable_ad_user"}


def _parse_iso_utc(s: str) -> str:
    """Parse a client UTC ISO string (e.g. '2026-06-25T14:30:00.000Z') into the
    'YYYY-MM-DD HH:MM:SS' form the scheduler compares against. '' if invalid."""
    s = (s or "").strip().replace("Z", "").split(".")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
    return ""


@app.route("/api/schedule", methods=["POST"])
def schedule_action() -> Any:
    """Queue a create/edit/offboard/enable action to run at a future UTC time.
    Body: {task_type, upn, run_at (UTC ISO), payload:{...}}."""
    data      = request.get_json(force=True) or {}
    task_type = (data.get("task_type") or "").strip()
    if task_type not in _SCHED_TYPES:
        return jsonify({"error": "Invalid task_type"}), 400
    run_at = _parse_iso_utc(data.get("run_at", ""))
    if not run_at:
        return jsonify({"error": "A valid run_at (UTC ISO) is required"}), 400
    upn     = (data.get("upn") or "").strip().lower()
    payload = data.get("payload") or {}
    ts      = now_utc()
    db = get_db()
    db.execute(
        "INSERT INTO scheduled_tasks (task_type, upn, payload, run_at, status, created_at)"
        " VALUES (?, ?, ?, ?, 'pending', ?)",
        (task_type, upn, json.dumps(payload), run_at, ts),
    )
    db.execute(
        "INSERT INTO audit_log (user_id, full_name, action, details, ticket, actor, timestamp) VALUES (?,?,?,?,?,?,?)",
        (None, upn or "—", f"scheduled_{task_type}",
         f"{task_type.replace('_', ' ')} queued for {run_at} UTC", payload.get("ticket", ""),
         current_actor(), ts),
    )
    db.commit()
    return jsonify({"message": f"Action scheduled for {run_at} UTC", "run_at": run_at}), 201


@app.route("/api/scheduled")
def list_scheduled() -> Any:
    """All scheduled tasks — pending/running first, then recently completed."""
    rows = get_db().execute(
        "SELECT id, task_type, upn, run_at, status, result, created_at, completed_at"
        " FROM scheduled_tasks"
        " ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'running' THEN 1 ELSE 2 END,"
        "          run_at DESC"
        " LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/scheduled/<int:tid>", methods=["PATCH"])
def reschedule_task(tid: int) -> Any:
    """Change a task's run time. A pending task is rescheduled; a failed one is
    re-queued (set back to pending) so it runs again at the new time."""
    data   = request.get_json(force=True) or {}
    run_at = _parse_iso_utc(data.get("run_at", ""))
    if not run_at:
        return jsonify({"error": "A valid run_at (UTC ISO) is required"}), 400
    db  = get_db()
    row = db.execute("SELECT status FROM scheduled_tasks WHERE id=?", (tid,)).fetchone()
    if not row:
        return jsonify({"error": "Scheduled task not found"}), 404
    if row["status"] == "running":
        return jsonify({"error": "Task is currently running"}), 409
    if row["status"] not in ("pending", "failed", "cancelled"):
        return jsonify({"error": f"Cannot reschedule a '{row['status']}' task"}), 409
    db.execute(
        "UPDATE scheduled_tasks SET run_at=?, status='pending', result='', completed_at='' WHERE id=?",
        (run_at, tid),
    )
    db.commit()
    log_audit("schedule_updated", str(tid), f"Rescheduled task #{tid} to {run_at} UTC")
    return jsonify({"message": f"Rescheduled to {run_at} UTC", "run_at": run_at})


@app.route("/api/scheduled/<int:tid>", methods=["DELETE"])
def cancel_task(tid: int) -> Any:
    """Cancel a pending task so the worker no longer picks it up."""
    db  = get_db()
    row = db.execute("SELECT status FROM scheduled_tasks WHERE id=?", (tid,)).fetchone()
    if not row:
        return jsonify({"error": "Scheduled task not found"}), 404
    if row["status"] != "pending":
        return jsonify({"error": f"Only pending tasks can be cancelled (this is '{row['status']}')"}), 409
    db.execute(
        "UPDATE scheduled_tasks SET status='cancelled', completed_at=? WHERE id=?",
        (now_utc(), tid),
    )
    db.commit()
    log_audit("schedule_cancelled", str(tid), f"Cancelled scheduled task #{tid}")
    return jsonify({"message": "Scheduled task cancelled"})


@app.route("/api/graph/users/<string:upn>/licenses/<string:sku_id>", methods=["DELETE"])
def graph_remove_license(upn: str, sku_id: str) -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    try:
        _graph.remove_license(upn, sku_id)
        log_audit("license_removed", upn, f"M365 license {sku_id} removed")
        return jsonify({"message": f"License removed from {upn}"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/users/<string:upn>/licenses/remember", methods=["POST"])
def remember_offboard_licenses(upn: str) -> Any:
    """Persist the SKUs being removed at offboarding so they can be re-assigned on re-enable."""
    data = request.get_json(force=True) or {}
    skus = [s for s in (data.get("skus") or []) if s]
    db = get_db()
    if skus:
        db.execute(
            "INSERT INTO offboarded_licenses (upn, skus_json, updated_at) VALUES (?,?,?)"
            " ON CONFLICT (upn) DO UPDATE SET"
            " skus_json=EXCLUDED.skus_json, updated_at=EXCLUDED.updated_at",
            (upn, json.dumps(skus), now_utc()),
        )
        db.commit()
    return jsonify({"remembered": len(skus)})


@app.route("/api/graph/users/<string:upn>/licenses/remembered")
def get_remembered_licenses(upn: str) -> Any:
    """The SKUs removed when this user was offboarded (for re-assign on re-enable)."""
    db  = get_db()
    row = db.execute("SELECT skus_json FROM offboarded_licenses WHERE upn=?", (upn,)).fetchone()
    skus = json.loads(row["skus_json"]) if row else []
    return jsonify({"skus": skus})


# ── Graph — Groups ──────────────────────────────────────────────────────────────

@app.route("/api/graph/groups")
def graph_list_groups() -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    try:
        return jsonify(_graph.get_groups(request.args.get("q", "")))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/groups/<string:group_id>/members")
def graph_group_members(group_id: str) -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    try:
        return jsonify(_graph.get_group_members(group_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/groups/<string:group_id>/members", methods=["POST"])
def graph_add_to_group(group_id: str) -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    data = request.get_json(force=True) or {}
    upn  = data.get("upn", "").strip()
    if not upn:
        return jsonify({"error": "upn is required"}), 400
    try:
        user_id = _graph.get_user_id(upn)
        if not user_id:
            return jsonify({"error": f"User not found in Azure AD: {upn}"}), 404
        _graph.add_to_group(group_id, user_id)
        log_audit("m365_group_add", upn, f"Added to M365 group {group_id}")
        return jsonify({"message": f"{upn} added to group"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/graph/groups/<string:group_id>/members/<string:user_id>", methods=["DELETE"])
def graph_remove_from_group(group_id: str, user_id: str) -> Any:
    if _graph is None:
        return jsonify({"error": "Graph manager unavailable"}), 503
    try:
        _graph.remove_from_group(group_id, user_id)
        log_audit("m365_group_remove", user_id, f"Removed from M365 group {group_id}")
        return jsonify({"message": "Member removed from group"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Scheduled-task worker ─────────────────────────────────────────────────────

def _finish_task(conn: PGConnection, task: Any, status: str, result: str, ts: str) -> None:
    """Mark a task done/failed and record it in the audit log."""
    conn.execute(
        "UPDATE scheduled_tasks SET status=?, result=?, completed_at=? WHERE id=?",
        (status, result, ts, task["id"]),
    )
    conn.execute(
        "INSERT INTO audit_log (user_id, full_name, action, details, actor, timestamp) VALUES (?,?,?,?,?,?)",
        (None, task["upn"], f"scheduled_{task['task_type']}_{status}", result, "system (scheduled)", ts),
    )
    conn.commit()


# ── Scheduled operation handlers (run in the worker thread, no request context) ──

def _sched_create_user(conn: PGConnection, p: dict) -> str:
    """Create the local record + AD account, then queue the license assignment."""
    full_name = (p.get("full_name") or "").strip()
    upn       = (p.get("upn") or "").strip().lower()
    if not full_name or not upn:
        raise RuntimeError("full_name and upn are required")
    ts = now_utc()
    cur = conn.execute(
        """
        INSERT INTO users
          (full_name, upn, department, job_title, manager, location,
           license, start_date, notes, phone, mobile, country,
           description, contract_end_date, status, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?)
        RETURNING id
        """,
        (full_name, upn, p.get("department", ""), p.get("job_title", ""),
         p.get("manager", ""), p.get("location", ""), p.get("license", ""),
         p.get("start_date", ""), p.get("notes", ""), p.get("phone", ""),
         p.get("mobile", ""), p.get("country", ""), p.get("description", ""),
         p.get("contract_end_date", ""), ts, ts),
    )
    uid = cur.fetchone()["id"]
    conn.execute(
        "INSERT INTO audit_log (user_id, full_name, action, details, actor, timestamp) VALUES (?,?,?,?,?,?)",
        (uid, full_name, "onboarded", f"Onboarded (scheduled): {upn}", "system (scheduled)", ts),
    )
    conn.commit()

    note = "local record created"
    if _ad is not None:
        res = _ad.create_user(
            full_name=full_name, upn=upn, sam=(p.get("sam") or "").strip(),
            display_name=(p.get("display_name") or full_name).strip(),
            given_name=(p.get("given_name") or "").strip(),
            surname=(p.get("surname") or "").strip(),
            password=p.get("password", ""),
            department=p.get("department", ""), title=p.get("job_title", ""),
            manager=p.get("manager", ""), ou=p.get("ou", ""),
            must_change_password=bool(p.get("must_change_password", True)),
            phone=p.get("phone", ""), mobile=p.get("mobile", ""),
            country=p.get("country", ""), description=p.get("description", ""),
            contract_end_date=p.get("contract_end_date", ""),
            email=p.get("upn", ""), ad_groups=p.get("ad_groups", []),
        )
        note += f"; AD account created (delta sync: {(res or {}).get('delta_sync', 'unknown')})"

    sku = (p.get("sku_id") or "").strip()
    if sku and _graph is not None:
        conn.execute(
            "INSERT INTO scheduled_tasks (task_type, upn, payload, run_at, status, created_at)"
            " VALUES ('assign_license', ?, ?, ?, 'pending', ?)",
            (upn, sku, now_utc(), now_utc()),
        )
        conn.commit()
        note += "; license queued"
    return f"{full_name}: {note}"


def _sched_edit_ad_user(conn: PGConnection, upn: str, fields: dict) -> str:
    if _ad is None:
        raise RuntimeError("AD manager unavailable")
    _ad.update_user(upn, fields)
    sync_local_from_ad(upn, fields, conn)
    return f"AD account updated for {upn}"


def _sched_offboard_user(conn: PGConnection, p: dict) -> str:
    uid  = p.get("uid")
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        raise RuntimeError("User not found")
    ts = now_utc()
    conn.execute(
        "UPDATE users SET status='offboarded', end_date=?, ticket=?, reason=?, notes=?, updated_at=? WHERE id=?",
        (p.get("end_date", ""), p.get("ticket", ""), p.get("reason", ""),
         p.get("notes", user["notes"] or ""), ts, uid),
    )
    conn.commit()
    note = "marked offboarded"
    if p.get("disable_ad") and _ad is not None:
        result  = _ad.disable_user(user["upn"])
        removed = result.get("removed_groups", []) if isinstance(result, dict) else []
        if removed:
            conn.execute(
                "INSERT INTO ad_disabled_groups (upn, groups_json, updated_at) VALUES (?,?,?)"
                " ON CONFLICT (upn) DO UPDATE SET groups_json=EXCLUDED.groups_json, updated_at=EXCLUDED.updated_at",
                (user["upn"], json.dumps(removed), now_utc()),
            )
            conn.commit()
        note += f"; AD disabled (removed {len(removed)} group(s))"
    return f"{user['full_name']}: {note}"


def _sched_enable_ad_user(conn: PGConnection, upn: str) -> str:
    if _ad is None:
        raise RuntimeError("AD manager unavailable")
    row     = conn.execute("SELECT groups_json FROM ad_disabled_groups WHERE upn=?", (upn,)).fetchone()
    restore = json.loads(row["groups_json"]) if row else []
    _ad.enable_user(upn, restore_groups=restore)
    if row:
        conn.execute("DELETE FROM ad_disabled_groups WHERE upn=?", (upn,))
        conn.commit()
    return f"AD account enabled for {upn} (restored {len(restore)} group(s))"


def _minutes_since(stamp: str, now: str) -> float:
    """Minutes between two 'YYYY-MM-DD HH:MM:SS' timestamps (0 if unparseable)."""
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        return (datetime.strptime(now, fmt) - datetime.strptime(stamp, fmt)).total_seconds() / 60
    except Exception:
        return 0.0


def _run_scheduled_task(conn: PGConnection, task: Any) -> None:
    ts = now_utc()
    tt = task["task_type"]

    # Non-license actions: run once at their scheduled time.
    if tt in ("create_user", "edit_ad_user", "offboard_user", "enable_ad_user"):
        try:
            payload = json.loads(task["payload"] or "{}")
        except Exception:
            payload = {}
        try:
            if tt == "create_user":
                result = _sched_create_user(conn, payload)
            elif tt == "edit_ad_user":
                result = _sched_edit_ad_user(conn, task["upn"], payload)
            elif tt == "offboard_user":
                result = _sched_offboard_user(conn, payload)
            else:
                result = _sched_enable_ad_user(conn, task["upn"])
            _finish_task(conn, task, "done", result, ts)
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            _finish_task(conn, task, "failed", str(exc)[:250], ts)
        return

    if tt != "assign_license":
        _finish_task(conn, task, "failed", f"Unknown task type: {tt}", ts)
        return
    if _graph is None:
        _finish_task(conn, task, "failed", "Graph manager unavailable", ts)
        return

    upn = task["upn"]

    def _requeue(reason: str) -> bool:
        """Re-queue the task for a short retry if still within the wait window.
        Returns False once the cap is exceeded (caller should mark it failed)."""
        if _minutes_since(task["created_at"] or ts, ts) >= LICENSE_MAX_WAIT_MINUTES:
            return False
        next_run = (datetime.utcnow() + timedelta(minutes=LICENSE_RETRY_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE scheduled_tasks SET status='pending', run_at=?, result=? WHERE id=?",
            (next_run, f"{reason} — retry at {next_run} UTC", task["id"]),
        )
        conn.commit()
        return True

    # 1) Readiness — only assign once the account actually exists in Entra ID.
    try:
        user_id = _graph.get_user_id(upn)
    except Exception:
        user_id = None
    if not user_id:
        if not _requeue(f"Waiting for {upn} to sync to Entra ID"):
            _finish_task(conn, task, "failed",
                         f"{upn} did not appear in Entra ID within {LICENSE_MAX_WAIT_MINUTES} min "
                         f"— check the AD account was created and AD Connect sync is healthy", ts)
        return

    # 2) usageLocation is mandatory for assignLicense and won't fix itself — fail
    #    fast with an actionable message rather than retrying for hours.
    loc = usage_location_for(upn, conn)
    if not loc:
        _finish_task(conn, task, "failed",
                     f"No usageLocation for {upn}: set the user's country (2-letter ISO) "
                     f"or DEFAULT_USAGE_LOCATION, then reschedule from the Scheduled tab", ts)
        return

    # 3) Assign. Errors right after sync are often transient (the directory object
    #    isn't fully provisioned yet), so retry within the window instead of giving
    #    up on the first failure; only fail for good once the cap is reached.
    try:
        _graph.set_usage_location(upn, loc)
        _graph.assign_license(upn, task["payload"])
        _finish_task(conn, task, "done", f"License {task['payload']} assigned to {upn}", ts)
    except Exception as exc:
        msg = str(exc)[:180]
        if not _requeue(f"Assign failed ({msg})"):
            _finish_task(conn, task, "failed", f"Assignment failed for {upn}: {msg}", ts)


def _scheduler_loop() -> None:
    """Poll for due tasks once a minute and run them. Claims each task
    atomically so it stays safe even if more than one worker is running."""
    while True:
        try:
            conn = _connect()
            due = conn.execute(
                "SELECT * FROM scheduled_tasks WHERE status='pending' AND run_at <= ? ORDER BY run_at",
                (now_utc(),),
            ).fetchall()
            for task in due:
                claimed = conn.execute(
                    "UPDATE scheduled_tasks SET status='running' WHERE id=? AND status='pending'",
                    (task["id"],),
                )
                conn.commit()
                if claimed.rowcount:
                    _run_scheduled_task(conn, task)
            conn.close()
        except Exception:
            pass
        time.sleep(60)


_scheduler_started = False


def start_scheduler() -> None:
    """Start the background task worker once per process."""
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True
    threading.Thread(target=_scheduler_loop, daemon=True).start()


# ── App bootstrap ─────────────────────────────────────────────────────────────
# init_db is idempotent and runs in every process. When imported by gunicorn
# (production) the __main__ block never executes, so start the scheduler here.
# For `python app.py` (local dev) the __main__ block starts it, reloader-aware.
init_db()
if __name__ != "__main__":
    start_scheduler()


# ────────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Start the worker only in the reloader's child to avoid a duplicate poller.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_scheduler()
    if SSO_ENABLED:
        print(f"Auth: Entra SSO enabled — redirect URI {AUTH_REDIRECT_URI}")
    elif not (ADMIN_PASSWORD_HASH or ADMIN_PASSWORD):
        print("WARNING: No SSO and no ADMIN_PASSWORD set — login is "
              f"'{ADMIN_USERNAME}' / 'admin'. Configure SSO or set credentials in .env.")
    if not os.getenv("SECRET_KEY"):
        print("WARNING: No SECRET_KEY set — sessions reset on restart. Set SECRET_KEY in .env.")
    print("Starting User Management App on http://localhost:5050")
    app.run(debug=True, port=5050)
