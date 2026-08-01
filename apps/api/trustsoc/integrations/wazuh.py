from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from trustsoc.config import get_settings


class WazuhClient:
    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = str(settings.wazuh_url).rstrip("/")
        self.username = settings.wazuh_username
        self.password = settings.wazuh_password
        self.verify = settings.wazuh_verify_tls
        self._token: str | None = None

    async def authenticate(self) -> str:
        async with httpx.AsyncClient(verify=self.verify, timeout=20) as client:
            response = await client.post(
                f"{self.base_url}/security/user/authenticate",
                params={"raw": "true"},
                auth=(self.username, self.password),
            )
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                payload = response.json()
                token = payload.get("data", {}).get("token") or payload.get("token")
            else:
                token = response.text.strip().strip('"')
            if not token:
                raise RuntimeError("Wazuh API did not return an authentication token")
            self._token = token
            return token

    async def request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        token = self._token or await self.authenticate()
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(verify=self.verify, timeout=45) as client:
            response = await client.request(
                method, f"{self.base_url}{path}", headers=headers, **kwargs
            )
            if response.status_code == 401:
                headers["Authorization"] = f"Bearer {await self.authenticate()}"
                response = await client.request(
                    method, f"{self.base_url}{path}", headers=headers, **kwargs
                )
            response.raise_for_status()
            return response.json()

    async def agents(self, limit: int = 1000) -> dict[str, Any]:
        return await self.request(
            "GET",
            "/agents",
            params={"limit": limit, "sort": "+id"},
        )

    async def health(self) -> dict[str, Any]:
        return await self.request("GET", "/manager/status")


class WazuhIndexerClient:
    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = str(settings.wazuh_indexer_url).rstrip("/")
        self.username = settings.wazuh_indexer_username
        self.password = settings.wazuh_indexer_password
        self.verify = settings.wazuh_indexer_verify_tls
        self.alert_index = settings.wazuh_alert_index

    async def request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self.verify, timeout=60) as client:
            response = await client.request(
                method,
                f"{self.base_url}{path}",
                auth=(self.username, self.password),
                **kwargs,
            )
            if response.status_code == 404 and path.endswith("/_search"):
                return {"hits": {"total": {"value": 0}, "hits": []}}
            response.raise_for_status()
            return response.json()

    async def health(self) -> dict[str, Any]:
        return await self.request("GET", "/_cluster/health")

    async def alerts_since(self, since: datetime, limit: int) -> dict[str, Any]:
        normalized_since = since.astimezone(UTC).isoformat().replace("+00:00", "Z")
        query = {
            "size": limit,
            "track_total_hits": True,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"range": {"timestamp": {"gte": normalized_since}}},
        }
        return await self.request("POST", f"/{self.alert_index}/_search", json=query)
