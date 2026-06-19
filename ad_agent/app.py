"""
Tryzens AD Agent — runs ON-PREMISES on the DC (or any domain-joined Windows server).
Exposes a REST API secured by an API key so the Azure-hosted web app can perform
Active Directory operations without a VPN.

Start: python app.py
Production: uses waitress (pip install waitress)
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from functools import wraps
from typing import Any

from flask import Flask, jsonify, request

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

AGENT_VERSION = "2025.06.18-adsync"

API_KEY:  str = os.getenv("AGENT_API_KEY", "")
PORT:     int = int(os.getenv("AGENT_PORT", "5001"))
USERS_OU: str = os.getenv("AD_USERS_OU", "")

# Trigger an Azure AD Connect delta sync after creating a user (best-effort).
ADSYNC_ENABLED: bool = os.getenv("ADSYNC_ENABLED", "true").lower() in ("1", "true", "yes")
# Run sync on a remote AAD Connect server via WinRM; blank = run locally.
ADSYNC_SERVER:  str  = os.getenv("ADSYNC_SERVER", "")

app = Flask(__name__)


# ── Auth ────────────────────────────────────────────────────────────────────────

def require_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            return jsonify({"error": "Agent not configured — set AGENT_API_KEY in .env"}), 503
        key = request.headers.get("X-API-Key", "")
        if not secrets.compare_digest(key.encode(), API_KEY.encode()):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── PowerShell helpers ──────────────────────────────────────────────────────────

def _clean(value: str) -> str:
    return re.sub(r"[^\w\s@.\-]", "", value)[:128]


def _run(script: str, extra: dict[str, str] | None = None) -> tuple[str, str, int]:
    env = {**os.environ, **(extra or {})}
    r = subprocess.run(
        ["powershell", "-NonInteractive", "-NoProfile",
         "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=60, env=env,
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def _json_run(script: str, extra: dict[str, str] | None = None) -> list[dict[str, Any]]:
    out, err, rc = _run(script, extra)
    if rc != 0:
        raise RuntimeError(err or "AD command failed")
    if not out:
        return []
    raw = json.loads(out)
    if raw is None:
        return []
    return [raw] if isinstance(raw, dict) else list(raw)


# ── Health (no auth) ────────────────────────────────────────────────────────────

@app.route("/health")
def health() -> Any:
    return jsonify({"status": "ok", "agent": "Tryzens AD Agent", "version": AGENT_VERSION})


# ── AD Status ───────────────────────────────────────────────────────────────────

@app.route("/ad/status")
@require_key
def ad_status() -> Any:
    out, err, rc = _run(
        "Import-Module ActiveDirectory -ErrorAction Stop; "
        "Get-ADDomain | Select-Object DNSRoot,NetBIOSName | ConvertTo-Json -Compress"
    )
    if rc != 0:
        msg = (err.strip().splitlines() or ["Connection failed"])[-1]
        return jsonify({"connected": False, "error": msg})
    try:
        d = json.loads(out)
        return jsonify({"connected": True,
                        "domain":  d.get("DNSRoot", ""),
                        "netbios": d.get("NetBIOSName", "")})
    except (json.JSONDecodeError, AttributeError):
        return jsonify({"connected": False, "error": "Unexpected response"})


# ── Organisational Units ────────────────────────────────────────────────────────

@app.route("/ad/ous")
@require_key
def ad_ous() -> Any:
    try:
        script = r"""
Import-Module ActiveDirectory
$r = @(Get-ADOrganizationalUnit -Filter * -Properties Description |
    Select-Object Name,DistinguishedName,Description |
    Sort-Object DistinguishedName)
if ($r.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $r -Depth 2 -Compress }
"""
        return jsonify(_json_run(script))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


# ── UPN Suffixes ──────────────────────────────────────────────────────────────

@app.route("/ad/upn-suffixes")
@require_key
def ad_upn_suffixes() -> Any:
    """Return valid UPN suffixes: the domain DNS root plus any alternative
    forest UPN suffixes."""
    out, err, rc = _run(r"""
Import-Module ActiveDirectory
$d = (Get-ADDomain).DNSRoot
$s = @((Get-ADForest).UPNSuffixes)
$all = @(@($d) + $s | Where-Object { $_ } | Select-Object -Unique)
if ($all.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $all -Compress }
""")
    if rc != 0:
        return jsonify({"error": err or "Failed to read UPN suffixes"}), 500
    suffixes: list[str] = []
    if out and out != "[]":
        try:
            raw = json.loads(out)
            suffixes = [raw] if isinstance(raw, str) else list(raw)
        except json.JSONDecodeError:
            suffixes = []
    return jsonify(suffixes)


@app.route("/ad/upn-suffixes", methods=["POST"])
@require_key
def ad_add_upn_suffix() -> Any:
    """Add an alternative UPN suffix to the forest (needs Enterprise Admin rights)."""
    data   = request.get_json(force=True) or {}
    suffix = str(data.get("suffix", "")).strip()
    if not suffix:
        return jsonify({"error": "suffix is required"}), 400
    _, err, rc = _run(r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory
    Set-ADForest -Identity (Get-ADForest).Name -UPNSuffixes @{Add=$env:AD_SUFFIX}
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
""", {"AD_SUFFIX": suffix})
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"UPN suffix added: {suffix}"})


@app.route("/ad/upn-suffixes/<string:suffix>", methods=["DELETE"])
@require_key
def ad_remove_upn_suffix(suffix: str) -> Any:
    _, err, rc = _run(r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory
    Set-ADForest -Identity (Get-ADForest).Name -UPNSuffixes @{Remove=$env:AD_SUFFIX}
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
""", {"AD_SUFFIX": suffix})
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"UPN suffix removed: {suffix}"})


# ── AD Users ────────────────────────────────────────────────────────────────────

@app.route("/ad/users")
@require_key
def ad_users() -> Any:
    q = _clean(request.args.get("q", ""))
    try:
        if q:
            script = r"""
Import-Module ActiveDirectory
$wc = "*" + $env:AD_Q + "*"
$r = @(Get-ADUser -Filter {Name -like $wc -or SamAccountName -like $wc -or UserPrincipalName -like $wc} `
    -Properties DisplayName,EmailAddress,Department,Title,Enabled,DistinguishedName |
    Select-Object Name,SamAccountName,UserPrincipalName,DisplayName,EmailAddress,Department,Title,Enabled,DistinguishedName)
if ($r.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $r -Depth 2 -Compress }
"""
            return jsonify(_json_run(script, {"AD_Q": q}))
        script = r"""
Import-Module ActiveDirectory
$r = @(Get-ADUser -Filter * -Properties DisplayName,EmailAddress,Department,Title,Enabled,DistinguishedName |
    Select-Object Name,SamAccountName,UserPrincipalName,DisplayName,EmailAddress,Department,Title,Enabled,DistinguishedName)
if ($r.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $r -Depth 2 -Compress }
"""
        return jsonify(_json_run(script))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/ad/users/<string:upn>")
@require_key
def ad_get_user(upn: str) -> Any:
    out, _, rc = _run(r"""
Import-Module ActiveDirectory
$upn = $env:AD_UPN
$u = Get-ADUser -Filter {UserPrincipalName -eq $upn} `
    -Properties DisplayName,GivenName,Surname,EmailAddress,Department,Title,Enabled,DistinguishedName,Created,OfficePhone,MobilePhone,c,Description,Manager
if ($u) {
    $mgrUpn = ""
    if ($u.Manager) {
        try { $mgrUpn = (Get-ADUser -Identity $u.Manager -Properties UserPrincipalName).UserPrincipalName } catch {}
    }
    $u | Select-Object Name,SamAccountName,UserPrincipalName,DisplayName,GivenName,Surname,EmailAddress,
        Department,Title,Enabled,DistinguishedName,Created,OfficePhone,MobilePhone,
        @{N='Country';E={$_.c}},Description,@{N='ManagerUpn';E={$mgrUpn}} | ConvertTo-Json -Compress
}
""", {"AD_UPN": upn})
    if rc != 0 or not out:
        return jsonify({"error": "User not found in AD"}), 404
    try:
        return jsonify(json.loads(out))
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid AD response"}), 500


@app.route("/ad/users", methods=["POST"])
@require_key
def ad_create_user() -> Any:
    data = request.get_json(force=True) or {}
    required = ("full_name", "upn", "sam", "given_name", "surname", "password")
    missing = [f for f in required if not str(data.get(f, "")).strip()]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    groups = data.get("ad_groups", [])
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]
    groups_csv = ",".join(groups)

    _, err, rc = _run(r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory
    $p = @{
        Name                  = $env:AD_NAME
        SamAccountName        = $env:AD_SAM
        UserPrincipalName     = $env:AD_UPN
        GivenName             = $env:AD_GIVEN
        Surname               = $env:AD_SN
        Department            = $env:AD_DEPT
        Title                 = $env:AD_TITLE
        AccountPassword       = (ConvertTo-SecureString $env:AD_PASS -AsPlainText -Force)
        Enabled               = $true
        ChangePasswordAtLogon = [bool]::Parse($env:AD_MUST_CHANGE)
    }
    if ($env:AD_DISPLAY)  { $p.DisplayName  = $env:AD_DISPLAY }
    if ($env:AD_PHONE)    { $p.OfficePhone  = $env:AD_PHONE }
    if ($env:AD_MOBILE)   { $p.MobilePhone  = $env:AD_MOBILE }
    if ($env:AD_EMAIL)    { $p.EmailAddress = $env:AD_EMAIL }
    if ($env:AD_DESC)     { $p.Description  = $env:AD_DESC }
    if ($env:AD_END_DATE) { $p.AccountExpirationDate = [datetime]::Parse($env:AD_END_DATE) }
    # -Country sets the 'c' attribute, which only accepts a 2-letter ISO code.
    # A 2-letter value goes there; anything longer (e.g. a country name) is stored
    # as the friendly 'co' attribute instead so New-ADUser does not reject it.
    if ($env:AD_COUNTRY) {
        $cval = $env:AD_COUNTRY.Trim()
        if ($cval.Length -eq 2) { $p.Country = $cval.ToUpper() }
        else { $p.OtherAttributes = @{ co = $cval } }
    }
    $ou = $env:AD_OU
    if ($ou) { $p.Path = $ou }
    # Manager must be resolved to an AD object (UPN/SAM/email) — best-effort;
    # an unresolved manager is skipped rather than failing the create.
    $mgr = $env:AD_MANAGER
    if ($mgr) {
        $m = Get-ADUser -Filter {UserPrincipalName -eq $mgr -or SamAccountName -eq $mgr -or EmailAddress -eq $mgr} -ErrorAction SilentlyContinue
        if ($m) { $p.Manager = $m.DistinguishedName }
    }
    New-ADUser @p
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}

# Group membership is best-effort — failures here do not fail the create
$groups = $env:AD_GROUPS -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
foreach ($g in $groups) {
    try { Add-ADGroupMember -Identity $g -Members $env:AD_SAM -ErrorAction Stop } catch {}
}

# Kick off an Azure AD Connect delta sync (best-effort; ignored if ADSync is absent
# or a cycle is already running). Runs remotely if ADSYNC_SERVER is set.
if ($env:ADSYNC_ENABLED -eq 'True') {
    try {
        if ($env:ADSYNC_SERVER) {
            Invoke-Command -ComputerName $env:ADSYNC_SERVER -ScriptBlock {
                Start-ADSyncSyncCycle -PolicyType Delta
            } -ErrorAction Stop
        } else {
            Import-Module ADSync -ErrorAction Stop
            Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
        }
    } catch {}
}
""", {
        "AD_NAME":        str(data["full_name"]).strip(),
        "AD_DISPLAY":     str(data.get("display_name", "") or data.get("full_name", "")).strip(),
        "AD_SAM":         str(data["sam"]).strip(),
        "AD_UPN":         str(data["upn"]).strip(),
        "AD_GIVEN":       str(data.get("given_name", "")).strip(),
        "AD_SN":          str(data.get("surname", "")).strip(),
        "AD_DEPT":        str(data.get("department", "")),
        "AD_TITLE":       str(data.get("title", "")),
        "AD_MANAGER":     str(data.get("manager", "")).strip(),
        "AD_PASS":        str(data["password"]),
        "AD_OU":          str(data.get("ou", "") or USERS_OU),
        "AD_MUST_CHANGE": str(bool(data.get("must_change_password", True))),
        "AD_PHONE":       str(data.get("phone", "")),
        "AD_MOBILE":      str(data.get("mobile", "")),
        "AD_EMAIL":       str(data.get("email", "") or data.get("upn", "")).strip(),
        "AD_COUNTRY":     str(data.get("country", "")),
        "AD_DESC":        str(data.get("description", "")),
        "AD_END_DATE":    str(data.get("contract_end_date", "")),
        "AD_GROUPS":      groups_csv,
        "ADSYNC_ENABLED": "True" if ADSYNC_ENABLED else "False",
        "ADSYNC_SERVER":  ADSYNC_SERVER,
    })
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"AD account created for {data['upn']}"}), 201


@app.route("/ad/users/<string:upn>", methods=["PUT"])
@require_key
def ad_update_user(upn: str) -> Any:
    """Update attributes of an existing AD user. Only fields present in the body
    are touched; a present-but-empty field clears that attribute."""
    data = request.get_json(force=True) or {}
    field_map = {
        "given_name":   "F_GIVEN",
        "surname":      "F_SN",
        "display_name": "F_DISP",
        "department":   "F_DEPT",
        "title":        "F_TITLE",
        "email":        "F_EMAIL",
        "phone":        "F_PHONE",
        "mobile":       "F_MOBILE",
        "description":  "F_DESC",
        "country":      "F_COUNTRY",
        "manager":      "F_MANAGER",
        "new_upn":      "F_UPN",
    }
    extra = {env: ("" if data[key] is None else str(data[key]))
             for key, env in field_map.items() if key in data}
    if not extra:
        return jsonify({"error": "No fields to update"}), 400
    extra["AD_UPN"] = upn

    _, err, rc = _run(r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory
    $upn = $env:AD_UPN
    $u = Get-ADUser -Filter {UserPrincipalName -eq $upn} -ErrorAction Stop
    if (-not $u) { throw "User not found in AD: $upn" }

    $set = @{}
    $clear = @()
    $map = @(
        @('F_GIVEN','GivenName','givenName'),
        @('F_SN','Surname','sn'),
        @('F_DISP','DisplayName','displayName'),
        @('F_DEPT','Department','department'),
        @('F_TITLE','Title','title'),
        @('F_EMAIL','EmailAddress','mail'),
        @('F_PHONE','OfficePhone','telephoneNumber'),
        @('F_MOBILE','MobilePhone','mobile'),
        @('F_DESC','Description','description')
    )
    foreach ($f in $map) {
        $v = [Environment]::GetEnvironmentVariable($f[0])
        if ($null -eq $v) { continue }
        if ($v -eq '') { $clear += $f[2] } else { $set[$f[1]] = $v }
    }

    # Country: 2-letter -> 'c' via -Country; longer -> friendly 'co'; empty -> clear both
    $c = [Environment]::GetEnvironmentVariable('F_COUNTRY')
    if ($null -ne $c) {
        if ($c -eq '') { $clear += 'c'; $clear += 'co' }
        elseif ($c.Trim().Length -eq 2) { $set['Country'] = $c.Trim().ToUpper() }
        else { $set['Replace'] = @{ co = $c.Trim() } }
    }

    # Manager: resolve (UPN/SAM/email) -> DN; empty -> clear
    $mgr = [Environment]::GetEnvironmentVariable('F_MANAGER')
    if ($null -ne $mgr) {
        if ($mgr -eq '') { $clear += 'manager' }
        else {
            $m = Get-ADUser -Filter {UserPrincipalName -eq $mgr -or SamAccountName -eq $mgr -or EmailAddress -eq $mgr} -ErrorAction SilentlyContinue
            if ($m) { $set['Manager'] = $m.DistinguishedName }
        }
    }

    # UPN change (e.g. new suffix) — set only if provided; never cleared here.
    $newUpn = [Environment]::GetEnvironmentVariable('F_UPN')
    if ($newUpn) { $set['UserPrincipalName'] = $newUpn }

    if ($set.Count -gt 0)   { Set-ADUser -Identity $u @set }
    if ($clear.Count -gt 0) { Set-ADUser -Identity $u -Clear $clear }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
""", extra)
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"AD account updated for {upn}"})


@app.route("/ad/users/<string:upn>", methods=["DELETE"])
@require_key
def ad_delete_user(upn: str) -> Any:
    """Permanently delete an AD user account."""
    _, err, rc = _run(r"""
Import-Module ActiveDirectory
$upn = $env:AD_UPN
$u = Get-ADUser -Filter {UserPrincipalName -eq $upn} -ErrorAction Stop
if (-not $u) { throw "User not found in AD: $upn" }
Remove-ADUser -Identity $u -Confirm:$false
""", {"AD_UPN": upn})
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"AD account deleted: {upn}"})


@app.route("/ad/users/<string:upn>/disable", methods=["POST"])
@require_key
def ad_disable_user(upn: str) -> Any:
    """Disable AD account AND remove user from all groups. Returns the removed
    group DNs so the caller can restore them on a later enable."""
    out, err, rc = _run(r"""
Import-Module ActiveDirectory
$upn = $env:AD_UPN
$u = Get-ADUser -Filter {UserPrincipalName -eq $upn} -Properties MemberOf -ErrorAction Stop
if (-not $u) { throw "User not found in AD: $upn" }
$removed = @($u.MemberOf)
foreach ($groupDN in $removed) {
    try { Remove-ADGroupMember -Identity $groupDN -Members $u -Confirm:$false -ErrorAction Stop } catch {}
}
Disable-ADAccount -Identity $u
if ($removed.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $removed -Compress }
""", {"AD_UPN": upn})
    if rc != 0:
        return jsonify({"error": err}), 400
    removed: list[str] = []
    if out and out != "[]":
        try:
            raw = json.loads(out)
            removed = [raw] if isinstance(raw, str) else list(raw)
        except json.JSONDecodeError:
            removed = []
    return jsonify({"message": f"AD account disabled and removed from all groups: {upn}",
                    "removed_groups": removed})


@app.route("/ad/users/<string:upn>/enable", methods=["POST"])
@require_key
def ad_enable_user(upn: str) -> Any:
    """Re-enable a disabled AD account and optionally restore group memberships.
    Pass {"restore_groups": [<group DN>, ...]} to re-add the user to those groups."""
    data = request.get_json(silent=True) or {}
    restore = data.get("restore_groups", [])
    if isinstance(restore, str):
        restore = [restore]
    # Group DNs contain commas, so join with newlines and split on newlines in PS.
    groups_nl = "\n".join(g for g in restore if str(g).strip())
    _, err, rc = _run(r"""
Import-Module ActiveDirectory
$upn = $env:AD_UPN
$u = Get-ADUser -Filter {UserPrincipalName -eq $upn} -ErrorAction Stop
if (-not $u) { throw "User not found in AD: $upn" }
Enable-ADAccount -Identity $u
$groups = $env:AD_RESTORE_GROUPS -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
foreach ($g in $groups) {
    try { Add-ADGroupMember -Identity $g -Members $u -ErrorAction Stop } catch {}
}
""", {"AD_UPN": upn, "AD_RESTORE_GROUPS": groups_nl})
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"AD account enabled: {upn}", "restored_groups": len(restore)})


# ── AD Groups ───────────────────────────────────────────────────────────────────

@app.route("/ad/groups")
@require_key
def ad_groups() -> Any:
    q = _clean(request.args.get("q", ""))
    try:
        if q:
            script = r"""
Import-Module ActiveDirectory
$wc = "*" + $env:AD_Q + "*"
$r = @(Get-ADGroup -Filter {Name -like $wc} -Properties Description,GroupScope,GroupCategory |
    Select-Object Name,SamAccountName,GroupScope,GroupCategory,Description,DistinguishedName)
if ($r.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $r -Depth 2 -Compress }
"""
            return jsonify(_json_run(script, {"AD_Q": q}))
        script = r"""
Import-Module ActiveDirectory
$r = @(Get-ADGroup -Filter * -Properties Description,GroupScope,GroupCategory |
    Select-Object Name,SamAccountName,GroupScope,GroupCategory,Description,DistinguishedName)
if ($r.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $r -Depth 2 -Compress }
"""
        return jsonify(_json_run(script))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/ad/groups/<string:sam>/members")
@require_key
def ad_group_members(sam: str) -> Any:
    try:
        script = r"""
Import-Module ActiveDirectory
$r = @(Get-ADGroupMember -Identity $env:AD_GROUP_SAM |
    Select-Object Name,SamAccountName,objectClass,DistinguishedName)
if ($r.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $r -Depth 2 -Compress }
"""
        return jsonify(_json_run(script, {"AD_GROUP_SAM": sam}))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/ad/groups/<string:sam>/members", methods=["POST"])
@require_key
def ad_add_to_group(sam: str) -> Any:
    data = request.get_json(force=True) or {}
    user_sam = str(data.get("user_sam", "")).strip()
    if not user_sam:
        return jsonify({"error": "user_sam is required"}), 400
    _, err, rc = _run(r"""
Import-Module ActiveDirectory
Add-ADGroupMember -Identity $env:AD_GROUP_SAM -Members $env:AD_USER_SAM
""", {"AD_GROUP_SAM": sam, "AD_USER_SAM": user_sam})
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"{user_sam} added to {sam}"})


@app.route("/ad/groups/<string:sam>/members/<string:user_sam>", methods=["DELETE"])
@require_key
def ad_remove_from_group(sam: str, user_sam: str) -> Any:
    _, err, rc = _run(r"""
Import-Module ActiveDirectory
Remove-ADGroupMember -Identity $env:AD_GROUP_SAM -Members $env:AD_USER_SAM -Confirm:$false
""", {"AD_GROUP_SAM": sam, "AD_USER_SAM": user_sam})
    if rc != 0:
        return jsonify({"error": err}), 400
    return jsonify({"message": f"{user_sam} removed from {sam}"})


# ────────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        from waitress import serve
        print(f"AD Agent running on http://0.0.0.0:{PORT}  (waitress)")
        serve(app, host="0.0.0.0", port=PORT)
    except ImportError:
        print(f"waitress not installed — using Flask dev server on port {PORT}")
        app.run(host="0.0.0.0", port=PORT, debug=False)
