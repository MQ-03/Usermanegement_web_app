from __future__ import annotations

import os
from typing import Any

import msal
import requests

_BASE = "https://graph.microsoft.com/v1.0"
_SCOPES = ["https://graph.microsoft.com/.default"]


class GraphManager:
    """Microsoft Graph operations using app-only (client credentials) auth."""

    def __init__(self) -> None:
        self.tenant_id     = os.getenv("GRAPH_TENANT_ID", "")
        self.client_id     = os.getenv("GRAPH_CLIENT_ID", "")
        self.client_secret = os.getenv("GRAPH_CLIENT_SECRET", "")
        self._msal: msal.ConfidentialClientApplication | None = None

    def _app(self) -> msal.ConfidentialClientApplication:
        if self._msal is None:
            self._msal = msal.ConfidentialClientApplication(
                self.client_id,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}",
                client_credential=self.client_secret,
            )
        return self._msal

    def _token(self) -> str:
        result = self._app().acquire_token_silent(_SCOPES, account=None)
        if not result:
            result = self._app().acquire_token_for_client(scopes=_SCOPES)
        if "access_token" not in result:
            raise RuntimeError(result.get("error_description", "Token acquisition failed"))
        return result["access_token"]

    def _hdrs(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}

    @staticmethod
    def _check(r: requests.Response) -> None:
        """Raise RuntimeError with Graph's actual error message instead of a raw
        '404 Client Error' style string."""
        if r.status_code < 400:
            return
        msg = f"{r.status_code} {r.reason}"
        try:
            err = r.json().get("error", {})
            if isinstance(err, dict) and err.get("message"):
                msg = err["message"]
        except Exception:
            pass
        if r.status_code == 404:
            msg = (f"Not found in Azure AD — the account may not have synced from "
                   f"on-prem yet, or the UPN domain is not verified in this tenant. ({msg})")
        raise RuntimeError(msg)

    def _get(self, path: str) -> Any:
        r = requests.get(f"{_BASE}/{path}", headers=self._hdrs(), timeout=30)
        self._check(r)
        return r.json()

    def _post(self, path: str, data: dict) -> Any:
        r = requests.post(f"{_BASE}/{path}", json=data, headers=self._hdrs(), timeout=30)
        self._check(r)
        return r.json() if r.content else {}

    def _patch(self, path: str, data: dict) -> None:
        r = requests.patch(f"{_BASE}/{path}", json=data, headers=self._hdrs(), timeout=30)
        self._check(r)

    def _delete(self, path: str) -> None:
        r = requests.delete(f"{_BASE}/{path}", headers=self._hdrs(), timeout=30)
        self._check(r)

    # ── Connectivity ────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        if not (self.tenant_id and self.client_id and self.client_secret):
            return {"connected": False, "error": "GRAPH_TENANT_ID / CLIENT_ID / CLIENT_SECRET not set"}
        try:
            d = self._get("organization?$select=displayName")
            orgs = d.get("value", [])
            return {"connected": True, "org": orgs[0].get("displayName", "") if orgs else ""}
        except Exception as exc:
            return {"connected": False, "error": str(exc)[:250]}

    # ── Licenses ────────────────────────────────────────────────────────────────

    def get_licenses(self) -> list[dict]:
        """Return all subscribed SKUs with usage counts."""
        data = self._get(
            "subscribedSkus"
            "?$select=skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits"
        )
        return data.get("value", [])

    def get_user_licenses(self, upn: str) -> list[dict]:
        data = self._get(f"users/{upn}/licenseDetails?$select=id,skuId,skuPartNumber")
        return data.get("value", [])

    def set_usage_location(self, upn: str, code: str) -> None:
        """A 2-letter ISO usageLocation is required before a license can be assigned."""
        self._patch(f"users/{upn}", {"usageLocation": code})

    def assign_license(self, upn: str, sku_id: str) -> None:
        self._post(f"users/{upn}/assignLicense", {
            "addLicenses": [{"skuId": sku_id, "disabledPlans": []}],
            "removeLicenses": [],
        })

    def remove_license(self, upn: str, sku_id: str) -> None:
        self._post(f"users/{upn}/assignLicense", {
            "addLicenses": [],
            "removeLicenses": [sku_id],
        })

    # ── M365 Groups ─────────────────────────────────────────────────────────────

    def get_groups(self, query: str = "") -> list[dict]:
        if query:
            safe_q = query.replace("'", "").replace('"', "")[:64]
            path = (
                f"groups?$filter=startswith(displayName,'{safe_q}')"
                "&$select=id,displayName,groupTypes,mailEnabled,securityEnabled,description"
            )
        else:
            path = "groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,description"
        data = self._get(path)
        return data.get("value", [])

    def get_group_members(self, group_id: str) -> list[dict]:
        data = self._get(f"groups/{group_id}/members?$select=id,displayName,userPrincipalName,mail")
        return data.get("value", [])

    def user_in_group(self, user_id: str, group_id: str) -> bool:
        """True if user_id is a (transitive) member of group_id."""
        data = self._post(f"users/{user_id}/checkMemberGroups", {"groupIds": [group_id]})
        return group_id in (data.get("value", []) or [])

    def get_user_id(self, upn: str) -> str | None:
        try:
            return self._get(f"users/{upn}?$select=id").get("id")
        except Exception:
            return None

    def add_to_group(self, group_id: str, user_id: str) -> None:
        self._post(f"groups/{group_id}/members/$ref", {
            "@odata.id": f"{_BASE}/directoryObjects/{user_id}"
        })

    def remove_from_group(self, group_id: str, user_id: str) -> None:
        self._delete(f"groups/{group_id}/members/{user_id}/$ref")
