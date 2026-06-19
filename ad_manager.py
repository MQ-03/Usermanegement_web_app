from __future__ import annotations

import os
from typing import Any

import requests as _req

_TIMEOUT = 30


class ADAgentError(RuntimeError):
    """Error from the AD agent, carrying the HTTP status code when available."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ADManager:
    """
    HTTP client that forwards all AD operations to the on-premises AD Agent
    (ad_agent/app.py) running on the local DC.

    Required env vars:
        AD_AGENT_URL  — e.g. https://172.29.37.208:5001  or  https://agent.yourdomain.com
        AD_AGENT_KEY  — must match AGENT_API_KEY set in the agent's .env
    """

    def __init__(self) -> None:
        self.base_url = os.getenv("AD_AGENT_URL", "").rstrip("/")
        self.api_key  = os.getenv("AD_AGENT_KEY", "")

    def _hdrs(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            r = _req.request(method, f"{self.base_url}{path}", headers=self._hdrs(),
                             timeout=_TIMEOUT, verify=False, **kwargs)
            r.raise_for_status()
            return r.json() if r.content else {}
        except _req.exceptions.Timeout:
            raise RuntimeError(f"AD agent timed out — is the agent running at {self.base_url}?")
        except _req.exceptions.ConnectionError:
            raise RuntimeError(f"Cannot reach AD agent at {self.base_url} — check it is running and port 5001 is open")
        except _req.exceptions.HTTPError as exc:
            # Surface the agent's actual error message, falling back to the HTTP status.
            status = exc.response.status_code if exc.response is not None else None
            msg = f"AD agent returned HTTP {status}" if status else str(exc)[:200]
            if exc.response is not None:
                try:
                    msg = exc.response.json().get("error") or msg
                except Exception:
                    # Non-JSON body (e.g. an HTML error page) — surface its text.
                    body = (exc.response.text or "").strip()
                    if body:
                        msg = f"{msg}: {body[:200]}"
            raise ADAgentError(msg, status)
        except _req.exceptions.RequestException as exc:
            raise RuntimeError(str(exc)[:200])

    def _get(self, path: str, params: dict | None = None) -> Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, data: dict | None = None) -> Any:
        return self._request("POST", path, json=data or {})

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    # ── Connectivity ────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        if not self.base_url:
            return {"connected": False, "error": "AD_AGENT_URL not configured"}
        try:
            return self._get("/ad/status")
        except RuntimeError as exc:
            return {"connected": False, "error": str(exc)}

    # ── Users ────────────────────────────────────────────────────────────────────

    def search_users(self, query: str = "") -> list[dict]:
        return self._get("/ad/users", params={"q": query} if query else None)

    def get_user(self, upn: str) -> dict | None:
        try:
            return self._get(f"/ad/users/{upn}")
        except ADAgentError as exc:
            if exc.status_code == 404:
                return None
            raise

    def get_ous(self) -> list[dict]:
        return self._get("/ad/ous")

    def get_upn_suffixes(self) -> list[str]:
        return self._get("/ad/upn-suffixes")

    def add_upn_suffix(self, suffix: str) -> dict:
        return self._post("/ad/upn-suffixes", {"suffix": suffix})

    def remove_upn_suffix(self, suffix: str) -> dict:
        return self._delete(f"/ad/upn-suffixes/{suffix}")

    def create_user(
        self,
        full_name: str, upn: str, sam: str,
        given_name: str, surname: str, password: str,
        department: str = "", title: str = "",
        ou: str = "", must_change_password: bool = True,
        phone: str = "", mobile: str = "", country: str = "",
        description: str = "", contract_end_date: str = "",
        email: str = "", manager: str = "", display_name: str = "",
        ad_groups: list[str] | None = None,
    ) -> None:
        self._post("/ad/users", {
            "full_name": full_name, "upn": upn, "sam": sam,
            "display_name": display_name, "given_name": given_name, "surname": surname,
            "password": password, "department": department,
            "title": title, "manager": manager, "ou": ou,
            "must_change_password": must_change_password,
            "phone": phone, "mobile": mobile, "country": country,
            "description": description,
            "contract_end_date": contract_end_date,
            "email": email or upn,
            "ad_groups": ad_groups or [],
        })

    def update_user(self, upn: str, fields: dict) -> dict:
        return self._request("PUT", f"/ad/users/{upn}", json=fields)

    def delete_user(self, upn: str) -> dict:
        return self._delete(f"/ad/users/{upn}")

    def disable_user(self, upn: str) -> dict:
        """Returns {"message": ..., "removed_groups": [<DN>, ...]}."""
        return self._post(f"/ad/users/{upn}/disable")

    def enable_user(self, upn: str, restore_groups: list[str] | None = None) -> dict:
        return self._post(f"/ad/users/{upn}/enable", {"restore_groups": restore_groups or []})

    # ── Groups ───────────────────────────────────────────────────────────────────

    def search_groups(self, query: str = "") -> list[dict]:
        return self._get("/ad/groups", params={"q": query} if query else None)

    def get_group_members(self, sam: str) -> list[dict]:
        return self._get(f"/ad/groups/{sam}/members")

    def add_to_group(self, group_sam: str, user_sam: str) -> None:
        self._post(f"/ad/groups/{group_sam}/members", {"user_sam": user_sam})

    def remove_from_group(self, group_sam: str, user_sam: str) -> None:
        self._delete(f"/ad/groups/{group_sam}/members/{user_sam}")
