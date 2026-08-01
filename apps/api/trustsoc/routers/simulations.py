from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.audit import write_audit
from trustsoc.database import get_db
from trustsoc.dependencies import require_roles
from trustsoc.models import SimulationRun, TelemetrySource, User, UserRole
from trustsoc.schemas import SimulationCreate
from trustsoc.worker import execute_simulation

router = APIRouter(prefix="/simulations", tags=["authorized simulations"])


@router.post("", status_code=202)
async def create_simulation(
    payload: SimulationCreate,
    user: User = Depends(
        require_roles(UserRole.tenant_admin, UserRole.red_team_operator, UserRole.soc_manager)
    ),
    db: AsyncSession = Depends(get_db),
):
    source = await db.scalar(
        select(TelemetrySource).where(
            TelemetrySource.id == payload.source_id,
            TelemetrySource.organization_id == user.organization_id,
        )
    )
    if source is None:
        raise HTTPException(404, "Source not found")
    run = SimulationRun(
        organization_id=user.organization_id,
        source_id=payload.source_id,
        simulation_type=payload.simulation_type,
        parameters={
            **payload.parameters,
            "authorization_reference": payload.authorization_reference,
        },
        authorized_by=user.id,
    )
    db.add(run)
    await db.flush()
    await write_audit(
        db,
        action="simulation.authorized",
        resource_type="simulation",
        resource_id=str(run.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details={
            "type": payload.simulation_type,
            "authorization_reference": payload.authorization_reference,
        },
    )
    await db.commit()
    execute_simulation.delay(str(run.id))
    return {
        "id": run.id,
        "status": "queued",
        "safety": "Synthetic telemetry impairment only; no destructive action executed.",
    }
