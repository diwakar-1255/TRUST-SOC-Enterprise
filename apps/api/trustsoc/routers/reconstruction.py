from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.database import get_db
from trustsoc.dependencies import current_user
from trustsoc.models import TelemetryEvent, TelemetrySource, User
from trustsoc.schemas import ReconstructedEvent, ReconstructionRequest
from trustsoc.services.reconstruction import reconstruct

router = APIRouter(prefix="/reconstruction", tags=["evidence reconstruction"])


@router.post("/timeline", response_model=list[ReconstructedEvent])
async def timeline(
    payload: ReconstructionRequest,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(TelemetryEvent, TelemetrySource)
        .join(TelemetrySource, TelemetrySource.id == TelemetryEvent.source_id)
        .where(
            TelemetryEvent.organization_id == user.organization_id,
            TelemetrySource.asset_id == payload.asset_id,
            TelemetryEvent.observed_at >= payload.start,
            TelemetryEvent.observed_at <= payload.end,
        )
        .order_by(TelemetryEvent.observed_at)
    )
    rows = (await db.execute(query)).all()
    events = [
        {
            "id": event.id,
            "event_type": event.event_type,
            "observed_at": event.observed_at,
            "body": event.body,
            "classification": event.classification,
            "source_type": source.source_type,
        }
        for event, source in rows
    ]
    return reconstruct(events)
