from __future__ import annotations

from typing import Any

import httpx

from trustsoc.config import get_settings


class HoneypotClient:
    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = str(settings.honeypot_api_url).rstrip("/")
        self.verify_tls = settings.honeypot_verify_tls
        self.headers: dict[str, str] = {"Accept": "application/json"}
        token = settings.honeypot_api_token.strip()
        header_name = settings.honeypot_api_token_header.strip()
        if token and header_name:
            self.headers[header_name] = token

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.verify_tls,
            headers=self.headers,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
            follow_redirects=False,
        ) as client:
            response = await client.get(path, params=params)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Honeypot API returned a non-object response")
            return payload

    async def health(self) -> dict[str, Any]:
        return await self._get("/")

    async def stats(self) -> dict[str, Any]:
        return await self._get("/stats")

    async def recent_events(self, limit: int) -> list[dict[str, Any]]:
        payload = await self._get("/events/recent", {"limit": min(limit, 100)})
        return list(payload.get("events") or [])

    async def alerts(self, limit: int) -> list[dict[str, Any]]:
        payload = await self._get(
            "/alerts",
            {"limit": min(limit, 100), "status": "open"},
        )
        return list(payload.get("alerts") or [])

    async def attackers(self, limit: int) -> list[dict[str, Any]]:
        payload = await self._get("/attackers", {"limit": min(limit, 100)})
        return list(payload.get("attackers") or [])
