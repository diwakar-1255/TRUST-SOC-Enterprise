from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.config import get_settings
from trustsoc.database import get_db
from trustsoc.dependencies import current_user
from trustsoc.models import (
    AlertGroup,
    Asset,
    DetectionRule,
    IntegrationState,
    SecurityAlert,
    SecurityIncident,
    SourceStatus,
    TelemetryEvent,
    TelemetrySource,
    User,
)
from trustsoc.schemas import (
    IntegrationStatusOut,
    PortalAsset,
    PortalSummary,
    SecurityAlertOut,
    SeverityCounts,
)

router = APIRouter(prefix="/portal", tags=["customer portal"])


def _integration_payload(state: IntegrationState | None) -> IntegrationStatusOut:
    settings = get_settings()
    metadata = state.metadata_json if state else {}
    return IntegrationStatusOut(
        enabled=settings.wazuh_enabled,
        status=state.status if state else ("configured" if settings.wazuh_enabled else "disabled"),
        manager_connected=bool(metadata.get("manager_connected", False)),
        indexer_connected=bool(metadata.get("indexer_connected", False)),
        last_attempt_at=state.last_attempt_at if state else None,
        last_success_at=state.last_success_at if state else None,
        last_error=state.last_error if state else None,
        synchronized_agents=state.synchronized_agents if state else 0,
        synchronized_alerts=state.synchronized_alerts if state else 0,
    )


@router.get("/summary", response_model=PortalSummary)
async def portal_summary(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org = user.organization_id
    since = datetime.now(UTC) - timedelta(hours=24)

    assets = int(
        await db.scalar(
            select(func.count())
            .select_from(Asset)
            .where(Asset.organization_id == org, Asset.active.is_(True))
        )
        or 0
    )
    sources = int(
        await db.scalar(
            select(func.count())
            .select_from(TelemetrySource)
            .where(
                TelemetrySource.organization_id == org,
                TelemetrySource.active.is_(True),
            )
        )
        or 0
    )
    critical_sources = int(
        await db.scalar(
            select(func.count())
            .select_from(TelemetrySource)
            .where(
                TelemetrySource.organization_id == org,
                TelemetrySource.active.is_(True),
                TelemetrySource.status == SourceStatus.critical,
            )
        )
        or 0
    )
    enabled_rules = int(
        await db.scalar(
            select(func.count())
            .select_from(DetectionRule)
            .where(
                DetectionRule.organization_id == org,
                DetectionRule.enabled.is_(True),
            )
        )
        or 0
    )
    native_events = int(
        await db.scalar(
            select(func.count())
            .select_from(TelemetryEvent)
            .where(
                TelemetryEvent.organization_id == org,
                TelemetryEvent.received_at >= since,
            )
        )
        or 0
    )
    average_trust = float(
        await db.scalar(
            select(func.avg(TelemetrySource.trust_score)).where(
                TelemetrySource.organization_id == org,
                TelemetrySource.active.is_(True),
            )
        )
        or 0
    )

    severity_rows = (
        await db.execute(
            select(SecurityAlert.severity, func.count(SecurityAlert.id))
            .where(
                SecurityAlert.organization_id == org,
                SecurityAlert.event_timestamp >= since,
            )
            .group_by(SecurityAlert.severity)
        )
    ).all()
    severity_map = {str(name): int(count) for name, count in severity_rows}
    alerts_24h = sum(severity_map.values())
    grouped_alerts_24h = int(
        await db.scalar(
            select(func.count())
            .select_from(AlertGroup)
            .where(
                AlertGroup.organization_id == org,
                AlertGroup.last_seen >= since,
            )
        )
        or 0
    )
    suppressed_alerts_24h = int(
        await db.scalar(
            select(func.count())
            .select_from(AlertGroup)
            .where(
                AlertGroup.organization_id == org,
                AlertGroup.last_seen >= since,
                AlertGroup.status == "suppressed",
            )
        )
        or 0
    )
    open_incidents = int(
        await db.scalar(
            select(func.count())
            .select_from(SecurityIncident)
            .where(
                SecurityIncident.organization_id == org,
                SecurityIncident.status.in_(["open", "acknowledged", "investigating", "contained"]),
            )
        )
        or 0
    )

    recent_alerts = list(
        await db.scalars(
            select(SecurityAlert)
            .where(SecurityAlert.organization_id == org)
            .order_by(SecurityAlert.event_timestamp.desc())
            .limit(8)
        )
    )

    technique_counter: Counter[str] = Counter()
    technique_rows = await db.scalars(
        select(SecurityAlert.mitre_techniques).where(
            SecurityAlert.organization_id == org,
            SecurityAlert.event_timestamp >= since,
        )
    )
    for techniques in technique_rows:
        technique_counter.update(techniques or [])

    wazuh_sources = list(
        await db.scalars(
            select(TelemetrySource).where(
                TelemetrySource.organization_id == org,
                TelemetrySource.source_type == "wazuh_agent",
                TelemetrySource.active.is_(True),
            )
        )
    )
    active_agents = sum(source.status == SourceStatus.healthy for source in wazuh_sources)
    disconnected_agents = sum(source.status == SourceStatus.critical for source in wazuh_sources)

    state = await db.scalar(
        select(IntegrationState).where(
            IntegrationState.organization_id == org,
            IntegrationState.integration == "wazuh",
        )
    )

    return PortalSummary(
        telemetry_trust_score=round(average_trust, 2),
        protected_assets=assets,
        telemetry_sources=sources,
        critical_sources=critical_sources,
        enabled_detections=enabled_rules,
        events_24h=native_events + alerts_24h,
        wazuh_agents_total=len(wazuh_sources),
        wazuh_agents_active=active_agents,
        wazuh_agents_disconnected=disconnected_agents,
        alerts_24h=alerts_24h,
        grouped_alerts_24h=grouped_alerts_24h,
        suppressed_alerts_24h=suppressed_alerts_24h,
        open_incidents=open_incidents,
        severity=SeverityCounts(
            critical=severity_map.get("critical", 0),
            high=severity_map.get("high", 0),
            medium=severity_map.get("medium", 0),
            low=severity_map.get("low", 0),
        ),
        mitre_techniques=[
            {"technique": technique, "count": count}
            for technique, count in technique_counter.most_common(8)
        ],
        recent_alerts=recent_alerts,
        integration=_integration_payload(state),
    )


@router.get("/alerts", response_model=list[SecurityAlertOut])
async def list_portal_alerts(
    severity: str | None = Query(default=None),
    agent_name: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    statement = select(SecurityAlert).where(SecurityAlert.organization_id == user.organization_id)
    if severity:
        statement = statement.where(SecurityAlert.severity == severity.lower())
    if agent_name:
        statement = statement.where(SecurityAlert.agent_name.ilike(f"%{agent_name}%"))
    rows = await db.scalars(statement.order_by(SecurityAlert.event_timestamp.desc()).limit(limit))
    return list(rows)


@router.get("/assets", response_model=list[PortalAsset])
async def list_portal_assets(
    user: User = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    assets = list(
        await db.scalars(
            select(Asset)
            .where(Asset.organization_id == user.organization_id)
            .order_by(Asset.hostname)
        )
    )
    sources = list(
        await db.scalars(
            select(TelemetrySource).where(
                TelemetrySource.organization_id == user.organization_id,
                TelemetrySource.active.is_(True),
            )
        )
    )
    source_map: dict = {}
    for source in sources:
        if source.asset_id is not None:
            source_map.setdefault(source.asset_id, []).append(source)

    result: list[PortalAsset] = []
    for asset in assets:
        asset_sources = source_map.get(asset.id, [])
        source_health = "unknown"
        if any(item.status == SourceStatus.critical for item in asset_sources):
            source_health = "critical"
        elif any(item.status == SourceStatus.degraded for item in asset_sources):
            source_health = "degraded"
        elif asset_sources and all(item.status == SourceStatus.healthy for item in asset_sources):
            source_health = "healthy"
        last_seen = max(
            (item.last_heartbeat_at for item in asset_sources if item.last_heartbeat_at),
            default=None,
        )
        tags = asset.tags or {}
        result.append(
            PortalAsset(
                id=asset.id,
                hostname=asset.hostname,
                asset_type=asset.asset_type,
                operating_system=asset.operating_system,
                ip_address=dict(asset.tags or {}).get("ip_address"),
                criticality=asset.criticality,
                active=asset.active,
                wazuh_agent_id=tags.get("wazuh_agent_id"),
                wazuh_status=tags.get("wazuh_status"),
                telemetry_sources=len(asset_sources),
                source_health=source_health,
                last_seen=last_seen,
            )
        )
    return result
