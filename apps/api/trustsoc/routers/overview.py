from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.database import get_db
from trustsoc.dependencies import current_user
from trustsoc.models import (
    Asset,
    DetectionRule,
    SourceStatus,
    TelemetryEvent,
    TelemetrySource,
    User,
)

router = APIRouter(prefix="/overview", tags=["overview"])


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org = user.organization_id
    asset_count = await db.scalar(
        select(func.count())
        .select_from(Asset)
        .where(Asset.organization_id == org, Asset.active.is_(True))
    )
    source_count = await db.scalar(
        select(func.count())
        .select_from(TelemetrySource)
        .where(TelemetrySource.organization_id == org, TelemetrySource.active.is_(True))
    )
    critical_sources = await db.scalar(
        select(func.count())
        .select_from(TelemetrySource)
        .where(
            TelemetrySource.organization_id == org, TelemetrySource.status == SourceStatus.critical
        )
    )
    rule_count = await db.scalar(
        select(func.count())
        .select_from(DetectionRule)
        .where(DetectionRule.organization_id == org, DetectionRule.enabled.is_(True))
    )
    event_count = await db.scalar(
        select(func.count())
        .select_from(TelemetryEvent)
        .where(
            TelemetryEvent.organization_id == org,
            TelemetryEvent.received_at >= datetime.now(UTC) - timedelta(hours=24),
        )
    )
    avg_trust = await db.scalar(
        select(func.avg(TelemetrySource.trust_score)).where(
            TelemetrySource.organization_id == org, TelemetrySource.active.is_(True)
        )
    )
    return {
        "assets": asset_count or 0,
        "sources": source_count or 0,
        "critical_sources": critical_sources or 0,
        "enabled_rules": rule_count or 0,
        "events_24h": event_count or 0,
        "telemetry_trust_score": round(float(avg_trust or 0), 2),
    }
