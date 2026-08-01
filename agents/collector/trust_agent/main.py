import asyncio
import platform
import socket
from datetime import datetime, timezone

import httpx

from trust_agent.config import AgentSettings
from trust_agent.signer import sign_event
from trust_agent.spool import append, read, replace
from trust_agent.state import load_state, save_state


class Collector:
    def __init__(self, settings: AgentSettings):
        self.settings = settings
        self.state = load_state(settings.state_path)

    def heartbeat(self) -> dict:
        seq = self.state["sequence"] + 1
        event = {
            "source_id": self.settings.source_id,
            "sequence": seq,
            "event_type": "heartbeat",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "body": {
                "hostname": socket.gethostname(),
                "os": platform.platform(),
                "agent_version": "0.1.0",
                "status": "ok",
            },
            "previous_hash": self.state["last_hash"],
        }
        return sign_event(event, self.settings.shared_secret)

    async def send(self, event: dict) -> bool:
        async with httpx.AsyncClient(
            verify=self.settings.verify_tls, timeout=15
        ) as client:
            response = await client.post(
                f"{self.settings.api_url.rstrip('/')}/telemetry/ingest", json=event
            )
            if response.status_code == 200:
                self.state = {
                    "sequence": event["sequence"],
                    "last_hash": event["event_hash"],
                }
                save_state(self.settings.state_path, self.state)
                return True
            return False

    async def flush(self):
        remaining = []
        for event in read(self.settings.spool_path):
            try:
                if not await self.send(event):
                    remaining.append(event)
            except Exception:  # noqa: BLE001
                remaining.append(event)
        replace(self.settings.spool_path, remaining)

    async def run(self):
        while True:
            await self.flush()
            event = self.heartbeat()
            try:
                if not await self.send(event):
                    append(self.settings.spool_path, event)
            except Exception:  # noqa: BLE001
                append(self.settings.spool_path, event)
            await asyncio.sleep(self.settings.heartbeat_seconds)


def main():
    asyncio.run(Collector(AgentSettings()).run())


if __name__ == "__main__":
    main()
