from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.database import get_db
from trustsoc.dependencies import current_user
from trustsoc.models import Asset, DetectionRule, TelemetrySource, User
from trustsoc.schemas import BlindnessFinding
from trustsoc.services.blindness import build_blindness_finding

router = APIRouter(prefix="/blindness", tags=["detection blindness"])


@router.get("", response_model=list[BlindnessFinding])
async def blindness_map(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    sources = list(
        await db.scalars(
            select(TelemetrySource).where(
                TelemetrySource.organization_id == user.organization_id,
                TelemetrySource.active.is_(True),
            )
        )
    )
    rules = list(
        await db.scalars(
            select(DetectionRule).where(
                DetectionRule.organization_id == user.organization_id,
                DetectionRule.enabled.is_(True),
            )
        )
    )
    assets = list(
        await db.scalars(
            select(Asset).where(
                Asset.organization_id == user.organization_id, Asset.active.is_(True)
            )
        )
    )
    rules_data = [
        {
            "id": str(r.id),
            "external_id": r.external_id,
            "name": r.name,
            "severity": r.severity,
            "source_types": r.source_types,
            "required_fields": r.required_fields,
            "mitre_techniques": r.mitre_techniques,
            "protected_asset_types": r.protected_asset_types,
        }
        for r in rules
    ]
    assets_data = [
        {
            "id": str(a.id),
            "hostname": a.hostname,
            "asset_type": a.asset_type,
            "criticality": a.criticality,
        }
        for a in assets
    ]
    return [
        build_blindness_finding(
            source={
                "id": s.id,
                "name": s.name,
                "source_type": s.source_type,
                "status": s.status.value,
                "available_fields": s.expected_fields if s.status.value == "healthy" else [],
            },
            rules=rules_data,
            assets=assets_data,
            total_enabled_rules=len(rules_data),
        )
        for s in sources
    ]
