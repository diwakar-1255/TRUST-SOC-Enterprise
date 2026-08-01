from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.config import get_settings
from trustsoc.database import SessionLocal
from trustsoc.integrations.wazuh import WazuhClient, WazuhIndexerClient
from trustsoc.models import (
    Asset,
    IntegrationState,
    NoisePolicy,
    Organization,
    SecurityAlert,
    SourceStatus,
    TelemetrySource,
)
from trustsoc.security import encrypt_secret, generate_shared_secret
from trustsoc.services.alert_operations import upsert_alert_group

logger = structlog.get_logger()
_sync_lock = asyncio.Lock()


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = datetime.now(UTC)
    else:
        parsed = datetime.now(UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def severity_from_level(level: int) -> str:
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def source_status(agent_status: str) -> tuple[SourceStatus, float]:
    normalized = (agent_status or "unknown").lower()
    if normalized == "active":
        return SourceStatus.healthy, 100.0
    if normalized in {"pending", "enrolling"}:
        return SourceStatus.degraded, 70.0
    if normalized in {"disconnected", "never_connected"}:
        return SourceStatus.critical, 25.0
    return SourceStatus.unknown, 20.0


def normalize_alert(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source", {})
    rule = source.get("rule", {}) or {}
    agent = source.get("agent", {}) or {}
    manager = source.get("manager", {}) or {}
    decoder = source.get("decoder", {}) or {}
    mitre = rule.get("mitre", {}) or {}
    level = int(rule.get("level", 0) or 0)
    description = str(rule.get("description") or "Wazuh security alert")
    return {
        "external_id": f"{hit.get('_index', 'wazuh-alerts')}:{hit.get('_id', '')}",
        "event_timestamp": parse_timestamp(source.get("timestamp")),
        "agent_id": str(agent.get("id")) if agent.get("id") is not None else None,
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "manager_name": manager.get("name"),
        "rule_id": str(rule.get("id", "0")),
        "rule_level": level,
        "title": description[:500],
        "description": description,
        "severity": severity_from_level(level),
        "groups": _list(rule.get("groups")),
        "mitre_techniques": _list(mitre.get("id")),
        "mitre_tactics": _list(mitre.get("tactic")),
        "decoder_name": decoder.get("name"),
        "full_log": source.get("full_log"),
        "raw": source,
    }


async def _integration_state(
    db: AsyncSession, organization_id, for_update: bool = False
) -> IntegrationState:
    statement = select(IntegrationState).where(
        IntegrationState.organization_id == organization_id,
        IntegrationState.integration == "wazuh",
    )
    if for_update:
        statement = statement.with_for_update()
    state = await db.scalar(statement)
    if state is None:
        state = IntegrationState(
            organization_id=organization_id, integration="wazuh", status="unknown"
        )
        db.add(state)
        await db.flush()
    return state


async def _upsert_agents(
    db: AsyncSession, organization_id, agents: Iterable[dict[str, Any]]
) -> tuple[int, Counter]:
    synchronized = 0
    statuses: Counter = Counter()
    for agent in agents:
        agent_id = str(agent.get("id", ""))
        hostname = str(agent.get("name") or f"wazuh-agent-{agent_id}")
        agent_status = str(agent.get("status") or "unknown").lower()
        statuses[agent_status] += 1
        os_data = agent.get("os", {}) or {}
        os_name = (
            " ".join(str(part) for part in [os_data.get("name"), os_data.get("version")] if part)
            or "unknown"
        )

        asset = await db.scalar(
            select(Asset).where(
                Asset.organization_id == organization_id, Asset.hostname == hostname
            )
        )
        tags = {
            "integration": "wazuh",
            "wazuh_agent_id": agent_id,
            "wazuh_status": agent_status,
            "wazuh_ip": agent.get("ip"),
            "wazuh_manager": agent.get("manager"),
        }
        if asset is None:
            asset = Asset(
                organization_id=organization_id,
                hostname=hostname,
                asset_type="security_infrastructure" if agent_id == "000" else "endpoint",
                operating_system=os_name,
                criticality=5 if agent_id == "000" else 3,
                owner="Wazuh integration",
                tags=tags,
                active=True,
            )
            db.add(asset)
            await db.flush()
        else:
            asset.operating_system = os_name if os_name != "unknown" else asset.operating_system
            asset.tags = {**(asset.tags or {}), **tags}
            asset.active = True

        source_name = f"Wazuh:{agent_id}:{hostname}"
        telemetry_source = await db.scalar(
            select(TelemetrySource).where(
                TelemetrySource.organization_id == organization_id,
                TelemetrySource.name == source_name,
            )
        )
        mapped_status, trust = source_status(agent_status)
        last_seen_value = agent.get("lastKeepAlive") or agent.get("dateAdd")
        last_seen = (
            parse_timestamp(last_seen_value)
            if last_seen_value
            else (datetime.now(UTC) if agent_status == "active" else None)
        )
        if telemetry_source is None:
            telemetry_source = TelemetrySource(
                organization_id=organization_id,
                asset_id=asset.id,
                name=source_name,
                source_type="wazuh_agent",
                encrypted_shared_secret=encrypt_secret(generate_shared_secret()),
                expected_heartbeat_seconds=180,
                expected_fields=["agent.id", "agent.name", "agent.status"],
                last_heartbeat_at=last_seen,
                status=mapped_status,
                trust_score=trust,
                active=True,
            )
            db.add(telemetry_source)
        else:
            telemetry_source.asset_id = asset.id
            telemetry_source.last_heartbeat_at = last_seen
            telemetry_source.status = mapped_status
            telemetry_source.trust_score = trust
            telemetry_source.active = True
        synchronized += 1
    return synchronized, statuses


async def _upsert_alerts(
    db: AsyncSession, organization_id, hits: list[dict[str, Any]]
) -> tuple[int, int, int]:
    normalized = [normalize_alert(hit) for hit in hits]
    external_ids = [item["external_id"] for item in normalized]
    existing: set[str] = set()
    if external_ids:
        existing = set(
            await db.scalars(
                select(SecurityAlert.external_id).where(
                    SecurityAlert.organization_id == organization_id,
                    SecurityAlert.external_id.in_(external_ids),
                )
            )
        )
    policies = list(
        await db.scalars(
            select(NoisePolicy).where(
                NoisePolicy.organization_id == organization_id,
                NoisePolicy.enabled.is_(True),
            )
        )
    )
    criticalities = {
        asset.hostname: asset.criticality
        for asset in await db.scalars(select(Asset).where(Asset.organization_id == organization_id))
    }
    created = 0
    groups_created = 0
    incidents_created = 0
    for item in normalized:
        if item["external_id"] in existing:
            continue
        alert = SecurityAlert(organization_id=organization_id, integration="wazuh", **item)
        db.add(alert)
        await db.flush()
        group, group_created, incident_created = await upsert_alert_group(
            db,
            alert,
            policies,
            asset_criticality=criticalities.get(alert.agent_name or "", 3),
        )
        incidents_created += int(incident_created)
        created += 1
        groups_created += int(group_created)
    return created, groups_created, incidents_created


async def _sync_wazuh_impl(organization_id=None) -> dict[str, Any]:
    settings = get_settings()
    if not settings.wazuh_enabled:
        return {"status": "disabled", "agents": 0, "alerts_created": 0}

    async with SessionLocal() as db:
        if organization_id is None:
            organization = await db.scalar(
                select(Organization).where(Organization.name == settings.bootstrap_org_name)
            )
            if organization is None:
                organization = await db.scalar(
                    select(Organization)
                    .where(Organization.active.is_(True))
                    .order_by(Organization.created_at)
                )
            if organization is None:
                raise RuntimeError("No active organization is available for Wazuh synchronization")
            organization_id = organization.id

        state = await _integration_state(db, organization_id, for_update=True)
        state.last_attempt_at = datetime.now(UTC)
        state.status = "syncing"
        state.last_error = None
        await db.commit()

    manager_connected = False
    indexer_connected = False
    try:
        manager_client = WazuhClient()
        indexer_client = WazuhIndexerClient()
        agents_payload, indexer_health = await asyncio.gather(
            manager_client.agents(), indexer_client.health()
        )
        manager_connected = True
        indexer_connected = True
        agents = agents_payload.get("data", {}).get("affected_items", [])

        async with SessionLocal() as db:
            state = await _integration_state(db, organization_id)
            since = (
                state.last_success_at
                or datetime.now(UTC) - timedelta(hours=settings.wazuh_alert_lookback_hours)
            ) - timedelta(minutes=5)

        alert_payload = await indexer_client.alerts_since(since, settings.wazuh_alert_batch_size)
        hits = alert_payload.get("hits", {}).get("hits", [])

        async with SessionLocal() as db:
            synchronized_agents, status_counts = await _upsert_agents(db, organization_id, agents)
            alerts_created, groups_created, incidents_created = await _upsert_alerts(
                db, organization_id, hits
            )
            state = await _integration_state(db, organization_id)
            state.status = "connected"
            state.last_success_at = datetime.now(UTC)
            state.last_error = None
            state.synchronized_agents = synchronized_agents
            state.synchronized_alerts += alerts_created
            state.metadata_json = {
                "manager_connected": manager_connected,
                "indexer_connected": indexer_connected,
                "indexer_cluster_status": indexer_health.get("status"),
                "agent_statuses": dict(status_counts),
                "alerts_examined": len(hits),
            }
            await db.commit()

        result = {
            "status": "connected",
            "agents": synchronized_agents,
            "agent_statuses": dict(status_counts),
            "alerts_examined": len(hits),
            "alerts_created": alerts_created,
            "groups_created": groups_created,
            "incidents_created": incidents_created,
            "manager_connected": manager_connected,
            "indexer_connected": indexer_connected,
        }
        logger.info("wazuh_sync_complete", **result)
        return result
    except Exception as exc:
        async with SessionLocal() as db:
            state = await _integration_state(db, organization_id)
            state.status = "error"
            state.last_error = f"{type(exc).__name__}: {str(exc)[:1000]}"
            state.metadata_json = {
                "manager_connected": manager_connected,
                "indexer_connected": indexer_connected,
            }
            await db.commit()
        logger.exception("wazuh_sync_failed", error=type(exc).__name__)
        raise


async def sync_wazuh(organization_id=None) -> dict[str, Any]:
    if _sync_lock.locked():
        return {
            "status": "already_running",
            "agents": 0,
            "alerts_created": 0,
        }
    async with _sync_lock:
        return await _sync_wazuh_impl(organization_id)


async def wazuh_sync_loop(stop_event: asyncio.Event) -> None:
    settings = get_settings()
    while not stop_event.is_set():
        try:
            await sync_wazuh()
        except Exception as exc:
            logger.warning("wazuh_background_sync_retry", error=type(exc).__name__)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=settings.wazuh_sync_interval_seconds)
        except TimeoutError:
            continue
