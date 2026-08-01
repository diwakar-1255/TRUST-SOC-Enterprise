from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.database import get_db
from trustsoc.dependencies import current_user
from trustsoc.models import HoneypotAttacker, HoneypotEvent, IntegrationState, SecurityAlert, User
from trustsoc.schemas import (
    HoneypotAttackerOut,
    HoneypotEventOut,
    HoneypotIntegrationStatusOut,
    HoneypotSummaryOut,
)
from trustsoc.services.honeypot_sync import _status_payload

router = APIRouter(prefix="/portal/honeypot", tags=["honeypot intelligence"])


@router.get("/summary", response_model=HoneypotSummaryOut)
async def honeypot_summary(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    state = await db.scalar(
        select(IntegrationState).where(
            IntegrationState.organization_id == user.organization_id,
            IntegrationState.integration == "honeypot",
        )
    )
    metadata = dict(state.metadata_json or {}) if state else {}
    stats = dict(metadata.get("stats") or {})
    by_service = {str(name): int(count) for name, count in stats.get("by_service", [])}
    alerts_by_severity = {
        str(name).lower(): int(count) for name, count in stats.get("alerts_by_severity", [])
    }

    events = list(
        await db.scalars(
            select(HoneypotEvent)
            .where(HoneypotEvent.organization_id == user.organization_id)
            .order_by(HoneypotEvent.observed_at.desc())
            .limit(20)
        )
    )
    attackers = list(
        await db.scalars(
            select(HoneypotAttacker)
            .where(HoneypotAttacker.organization_id == user.organization_id)
            .order_by(HoneypotAttacker.risk_score.desc(), HoneypotAttacker.total_events.desc())
            .limit(10)
        )
    )
    critical_alerts = list(
        await db.scalars(
            select(SecurityAlert)
            .where(
                SecurityAlert.organization_id == user.organization_id,
                SecurityAlert.integration == "honeypot",
                SecurityAlert.severity.in_(["critical", "high"]),
            )
            .order_by(SecurityAlert.event_timestamp.desc())
            .limit(10)
        )
    )
    return HoneypotSummaryOut(
        integration=HoneypotIntegrationStatusOut(**_status_payload(state)),
        by_service=by_service,
        alerts_by_severity=alerts_by_severity,
        recent_events=events,
        top_attackers=attackers,
        critical_alerts=critical_alerts,
    )


@router.get("/events", response_model=list[HoneypotEventOut])
async def list_honeypot_events(
    severity: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(UTC) - timedelta(hours=hours)
    statement = select(HoneypotEvent).where(
        HoneypotEvent.organization_id == user.organization_id,
        HoneypotEvent.observed_at >= since,
    )
    if severity:
        statement = statement.where(HoneypotEvent.severity == severity.lower())
    if source_ip:
        statement = statement.where(HoneypotEvent.source_ip == source_ip)
    return list(await db.scalars(statement.order_by(HoneypotEvent.observed_at.desc()).limit(limit)))


@router.get("/attackers", response_model=list[HoneypotAttackerOut])
async def list_honeypot_attackers(
    minimum_risk: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    statement = (
        select(HoneypotAttacker)
        .where(
            HoneypotAttacker.organization_id == user.organization_id,
            HoneypotAttacker.risk_score >= minimum_risk,
        )
        .order_by(HoneypotAttacker.risk_score.desc(), HoneypotAttacker.total_events.desc())
        .limit(limit)
    )
    return list(await db.scalars(statement))
