from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select

from trustsoc.config import get_settings
from trustsoc.database import SessionLocal
from trustsoc.integrations.honeypot import HoneypotClient
from trustsoc.models import (
    Asset,
    HoneypotAttacker,
    HoneypotEvent,
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
_MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _severity(value: Any) -> str:
    normalized = str(value or "low").strip().lower()
    return normalized if normalized in {"critical", "high", "medium", "low"} else "low"


def _rule_level(severity: str) -> int:
    return {"critical": 15, "high": 12, "medium": 8, "low": 3}[severity]


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "unknown").strip().lower()).strip("_")


def _rule_id(item: dict[str, Any]) -> str:
    service = _slug(item.get("service"))[:20]
    attack_type = _slug(item.get("attack_type") or item.get("event_type"))[:60]
    return f"HP-{service}-{attack_type}"[:100]


def _groups(item: dict[str, Any]) -> list[str]:
    values = ["honeypot"]
    for key in ("service", "event_type", "attack_type"):
        value = _slug(item.get(key))
        if value and value not in values:
            values.append(value)
    return values


def _mitre(item: dict[str, Any]) -> list[str]:
    return _MITRE_PATTERN.findall(str(item.get("mitre_technique") or ""))


def _status_payload(state: IntegrationState | None) -> dict[str, Any]:
    settings = get_settings()
    metadata = dict(state.metadata_json or {}) if state else {}
    stats = dict(metadata.get("stats") or {})
    return {
        "enabled": settings.honeypot_enabled,
        "status": (
            state.status if state else ("configured" if settings.honeypot_enabled else "disabled")
        ),
        "api_connected": bool(metadata.get("api_connected", False)),
        "grafana_url": str(settings.honeypot_grafana_url),
        "last_attempt_at": state.last_attempt_at if state else None,
        "last_success_at": state.last_success_at if state else None,
        "last_error": state.last_error if state else None,
        "synchronized_events": int(metadata.get("synchronized_events", 0)),
        "synchronized_alerts": state.synchronized_alerts if state else 0,
        "synchronized_attackers": int(metadata.get("synchronized_attackers", 0)),
        "total_events": int(stats.get("total_events", 0)),
        "total_alerts": int(stats.get("total_alerts", 0)),
        "total_attackers": int(stats.get("total_attackers", 0)),
    }


async def _upsert_event(db, organization_id: UUID, item: dict[str, Any]) -> bool:
    external_id = str(item.get("id") or "").strip()
    if not external_id:
        return False
    existing = await db.scalar(
        select(HoneypotEvent).where(
            HoneypotEvent.organization_id == organization_id,
            HoneypotEvent.external_event_id == external_id,
        )
    )
    if existing:
        return False
    db.add(
        HoneypotEvent(
            organization_id=organization_id,
            external_event_id=external_id,
            observed_at=_parse_datetime(item.get("timestamp")) or datetime.now(UTC),
            source_ip=str(item.get("source_ip") or "unknown"),
            service=str(item.get("service") or "unknown"),
            event_type=str(item.get("event_type") or "Honeypot event"),
            attack_type=str(item.get("attack_type") or "Unclassified activity"),
            username=str(item.get("username")) if item.get("username") is not None else None,
            path=str(item.get("path")) if item.get("path") is not None else None,
            user_agent=str(item.get("user_agent")) if item.get("user_agent") is not None else None,
            risk_score=int(item.get("risk_score") or 0),
            severity=_severity(item.get("severity")),
            geo=dict(item.get("geo") or {}),
            raw=item,
        )
    )
    return True


async def _upsert_attacker(db, organization_id: UUID, item: dict[str, Any]) -> bool:
    source_ip = str(item.get("source_ip") or "").strip()
    if not source_ip:
        return False
    attacker = await db.scalar(
        select(HoneypotAttacker).where(
            HoneypotAttacker.organization_id == organization_id,
            HoneypotAttacker.source_ip == source_ip,
        )
    )
    created = attacker is None
    if attacker is None:
        attacker = HoneypotAttacker(organization_id=organization_id, source_ip=source_ip)
        db.add(attacker)
    attacker.country = item.get("country")
    attacker.city = item.get("city")
    attacker.isp = item.get("isp")
    attacker.asn = item.get("asn")
    attacker.first_seen = _parse_datetime(item.get("first_seen"))
    attacker.last_seen = _parse_datetime(item.get("last_seen"))
    attacker.total_events = int(item.get("total_events") or 0)
    attacker.risk_score = int(item.get("risk_score") or 0)
    attacker.severity = _severity(item.get("severity"))
    attacker.raw = item
    attacker.updated_at = datetime.now(UTC)
    return created


async def _upsert_alert(
    db,
    organization_id: UUID,
    item: dict[str, Any],
    policies: list[NoisePolicy],
) -> tuple[bool, bool, bool]:
    source_id = str(item.get("id") or item.get("incident_id") or "").strip()
    if not source_id:
        return False, False, False
    external_id = f"honeypot-alert:{source_id}"
    alert = await db.scalar(
        select(SecurityAlert).where(
            SecurityAlert.organization_id == organization_id,
            SecurityAlert.external_id == external_id,
        )
    )
    severity = _severity(item.get("severity"))
    if alert is not None:
        alert.event_timestamp = (
            _parse_datetime(item.get("updated_at") or item.get("created_at"))
            or alert.event_timestamp
        )
        alert.agent_ip = str(item.get("source_ip") or "") or None
        alert.rule_level = _rule_level(severity)
        alert.title = str(item.get("title") or alert.title)
        alert.description = str(item.get("recommendation") or "")
        alert.severity = severity
        alert.groups = _groups(item)
        alert.mitre_techniques = _mitre(item)
        alert.raw = item
        alert.full_log = json.dumps(item, separators=(",", ":"), default=str)
        return False, False, False

    alert = SecurityAlert(
        organization_id=organization_id,
        external_id=external_id,
        integration="honeypot",
        event_timestamp=_parse_datetime(item.get("updated_at") or item.get("created_at"))
        or datetime.now(UTC),
        agent_id=str(item.get("service") or "honeypot").lower(),
        agent_name=f"Deployed {item.get('service') or 'Honeypot'} honeypot",
        agent_ip=str(item.get("source_ip") or "") or None,
        manager_name="deployed-honeypot-soc",
        rule_id=_rule_id(item),
        rule_level=_rule_level(severity),
        title=str(item.get("title") or "Honeypot security alert"),
        description=str(item.get("recommendation") or ""),
        severity=severity,
        groups=_groups(item),
        mitre_techniques=_mitre(item),
        mitre_tactics=[],
        decoder_name="honeypot_soc_api",
        full_log=json.dumps(item, separators=(",", ":"), default=str),
        status="new",
        raw=item,
    )
    db.add(alert)
    await db.flush()
    _, group_created, incident_created = await upsert_alert_group(db, alert, policies)
    return True, group_created, incident_created



async def _upsert_honeypot_inventory(
    db,
    organization_id: UUID,
    now: datetime,
    *,
    healthy: bool,
) -> None:
    """Represent the deployed honeypot as an asset and telemetry source."""

    asset = await db.scalar(
        select(Asset).where(
            Asset.organization_id == organization_id,
            Asset.hostname == "honeypot-vm",
        )
    )

    asset_values = {
        "organization_id": organization_id,
        "hostname": "honeypot-vm",
        "asset_type": "security_infrastructure",
        "operating_system": "Ubuntu Linux — Azure Honeypot SOC",
        "criticality": 5,
        "owner": "TRUST-SOC",
        "tags": {
            "integration": "honeypot",
            "platform": "azure",
            "ip_address": "52.237.90.251",
            "api_url": str(get_settings().honeypot_api_url),
        },
    }

    if asset is None:
        asset_columns = {
            column.key for column in Asset.__table__.columns
        }

        asset = Asset(
            **{
                key: value
                for key, value in asset_values.items()
                if key in asset_columns
            }
        )

        db.add(asset)
        await db.flush()
    else:
        if hasattr(asset, "asset_type"):
            asset.asset_type = "security_infrastructure"

        if hasattr(asset, "operating_system"):
            asset.operating_system = (
                "Ubuntu Linux — Azure Honeypot SOC"
            )

        if hasattr(asset, "criticality"):
            asset.criticality = 5

        if hasattr(asset, "owner"):
            asset.owner = "TRUST-SOC"

        if hasattr(asset, "tags"):
            tags = dict(asset.tags or {})
            tags.update(asset_values["tags"])
            asset.tags = tags

    if healthy and hasattr(asset, "last_seen"):
        asset.last_seen = now

    source_record = await db.scalar(
        select(TelemetrySource).where(
            TelemetrySource.organization_id == organization_id,
            TelemetrySource.name == "Honeypot SOC API",
        )
    )

    healthy_status = SourceStatus.healthy
    failed_status = getattr(
        SourceStatus,
        "critical",
        SourceStatus.unknown,
    )
    selected_status = healthy_status if healthy else failed_status

    source_values = {
        "organization_id": organization_id,
        "asset_id": asset.id,
        "name": "Honeypot SOC API",
        "source_type": "honeypot",
        "expected_heartbeat_seconds": max(
            180,
            int(get_settings().honeypot_sync_interval_seconds) * 3,
        ),
        "expected_fields": [
            "events",
            "alerts",
            "attackers",
            "stats",
        ],
        "encrypted_shared_secret": encrypt_secret(
            generate_shared_secret()
        ),
        "last_sequence": 0,
        "status": selected_status,
        "trust_score": 100 if healthy else 0,
        "last_heartbeat_at": now if healthy else None,
    }

    if source_record is None:
        source_columns = {
            column.key
            for column in TelemetrySource.__table__.columns
        }

        source_record = TelemetrySource(
            **{
                key: value
                for key, value in source_values.items()
                if key in source_columns
            }
        )

        db.add(source_record)
    else:
        if hasattr(source_record, "asset_id"):
            source_record.asset_id = asset.id

        if hasattr(source_record, "status"):
            source_record.status = selected_status

        if hasattr(source_record, "trust_score"):
            source_record.trust_score = 100 if healthy else 0

        if healthy and hasattr(
            source_record,
            "last_heartbeat_at",
        ):
            source_record.last_heartbeat_at = now

        if hasattr(
            source_record,
            "expected_heartbeat_seconds",
        ):
            source_record.expected_heartbeat_seconds = max(
                180,
                int(
                    get_settings().honeypot_sync_interval_seconds
                ) * 3,
            )

async def sync_honeypot(organization_id: UUID | None = None) -> dict[str, Any]:
    settings = get_settings()
    if not settings.honeypot_enabled:
        return {"status": "disabled"}
    if _sync_lock.locked():
        return {"status": "already_running"}

    async with _sync_lock:
        client = HoneypotClient()
        async with SessionLocal() as db:
            organizations = (
                [await db.get(Organization, organization_id)]
                if organization_id
                else list(
                    await db.scalars(select(Organization).where(Organization.active.is_(True)))
                )
            )
            organizations = [item for item in organizations if item is not None]
            if not organizations:
                return {"status": "no_organizations"}

            try:
                health, stats, events, alerts, attackers = await asyncio.gather(
                    client.health(),
                    client.stats(),
                    client.recent_events(settings.honeypot_event_batch_size),
                    client.alerts(settings.honeypot_alert_batch_size),
                    client.attackers(settings.honeypot_attacker_batch_size),
                )
                if str(health.get("status") or "").lower() != "ok":
                    raise RuntimeError("Honeypot API health check did not return status=ok")
            except Exception as exc:
                now = datetime.now(UTC)
                for org in organizations:
                    state = await db.scalar(
                        select(IntegrationState).where(
                            IntegrationState.organization_id == org.id,
                            IntegrationState.integration == "honeypot",
                        )
                    )
                    if state is None:
                        state = IntegrationState(organization_id=org.id, integration="honeypot")
                        db.add(state)
                    state.status = "error"
                    state.last_attempt_at = now
                    state.last_error = f"{type(exc).__name__}: {exc}"
                    state.metadata_json = {
                        **dict(state.metadata_json or {}),
                        "api_connected": False,
                    }
                    await _upsert_honeypot_inventory(
                        db,
                        org.id,
                        now,
                        healthy=False,
                    )
                await db.commit()
                logger.exception("honeypot_sync_failed", error_type=type(exc).__name__)
                raise

            totals = {
                "events_created": 0,
                "alerts_created": 0,
                "attackers_created": 0,
                "groups_created": 0,
                "incidents_created": 0,
            }
            now = datetime.now(UTC)
            for org in organizations:
                state = await db.scalar(
                    select(IntegrationState).where(
                        IntegrationState.organization_id == org.id,
                        IntegrationState.integration == "honeypot",
                    )
                )
                if state is None:
                    state = IntegrationState(organization_id=org.id, integration="honeypot")
                    db.add(state)

                await _upsert_honeypot_inventory(
                    db,
                    org.id,
                    now,
                    healthy=True,
                )

                policies = list(
                    await db.scalars(
                        select(NoisePolicy).where(
                            NoisePolicy.organization_id == org.id,
                            NoisePolicy.enabled.is_(True),
                        )
                    )
                )
                events_created = 0
                alerts_created = 0
                attackers_created = 0
                groups_created = 0
                incidents_created = 0
                for item in events:
                    events_created += int(await _upsert_event(db, org.id, item))
                for item in alerts:
                    created, group_created, incident_created = await _upsert_alert(
                        db, org.id, item, policies
                    )
                    alerts_created += int(created)
                    groups_created += int(group_created)
                    incidents_created += int(incident_created)
                for item in attackers:
                    attackers_created += int(await _upsert_attacker(db, org.id, item))

                metadata = dict(state.metadata_json or {})
                metadata.update(
                    {
                        "api_connected": True,
                        "health": health,
                        "stats": stats,
                        "synchronized_events": int(metadata.get("synchronized_events", 0))
                        + events_created,
                        "synchronized_attackers": int(metadata.get("synchronized_attackers", 0))
                        + attackers_created,
                        "events_examined": len(events),
                        "alerts_examined": len(alerts),
                        "attackers_examined": len(attackers),
                        "groups_created_last_sync": groups_created,
                        "incidents_created_last_sync": incidents_created,
                    }
                )
                state.status = "connected"
                state.last_attempt_at = now
                state.last_success_at = now
                state.last_error = None
                state.synchronized_agents = len(attackers)
                state.synchronized_alerts = int(state.synchronized_alerts or 0) + alerts_created
                state.metadata_json = metadata

                totals["events_created"] += events_created
                totals["alerts_created"] += alerts_created
                totals["attackers_created"] += attackers_created
                totals["groups_created"] += groups_created
                totals["incidents_created"] += incidents_created

            await db.commit()
            result = {
                "status": "connected",
                "api_connected": True,
                "events_examined": len(events),
                "alerts_examined": len(alerts),
                "attackers_examined": len(attackers),
                **totals,
                "stats": stats,
            }
            logger.info("honeypot_sync_complete", **result)
            return result


async def honeypot_sync_loop(stop_event: asyncio.Event) -> None:
    settings = get_settings()
    while not stop_event.is_set():
        try:
            await sync_honeypot()
        except Exception as exc:
            logger.warning("honeypot_background_sync_retry", error=type(exc).__name__)
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=settings.honeypot_sync_interval_seconds,
            )
        except TimeoutError:
            continue
