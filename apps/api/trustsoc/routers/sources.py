from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.audit import write_audit
from trustsoc.database import get_db
from trustsoc.dependencies import current_user, require_roles
from trustsoc.models import Asset, TelemetrySource, User, UserRole
from trustsoc.schemas import SourceCreate, SourceCreated, SourceOut
from trustsoc.security import encrypt_secret, generate_shared_secret

router = APIRouter(prefix="/sources", tags=["telemetry sources"])


@router.get("", response_model=list[SourceOut])
async def list_sources(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    result = await db.scalars(
        select(TelemetrySource)
        .where(TelemetrySource.organization_id == user.organization_id)
        .order_by(TelemetrySource.name)
    )
    return list(result)


@router.post("", response_model=SourceCreated, status_code=201)
async def create_source(
    payload: SourceCreate,
    user: User = Depends(require_roles(UserRole.tenant_admin, UserRole.soc_manager)),
    db: AsyncSession = Depends(get_db),
):
    if payload.asset_id:
        asset = await db.scalar(
            select(Asset).where(
                Asset.id == payload.asset_id, Asset.organization_id == user.organization_id
            )
        )
        if asset is None:
            raise HTTPException(404, "Asset not found")
    duplicate = await db.scalar(
        select(TelemetrySource).where(
            TelemetrySource.organization_id == user.organization_id,
            TelemetrySource.name == payload.name,
        )
    )
    if duplicate:
        raise HTTPException(409, "Telemetry source already exists")
    secret = generate_shared_secret()
    source = TelemetrySource(
        organization_id=user.organization_id,
        encrypted_shared_secret=encrypt_secret(secret),
        **payload.model_dump(),
    )
    db.add(source)
    await db.flush()
    await write_audit(
        db,
        action="source.create",
        resource_type="telemetry_source",
        resource_id=str(source.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details={"source_type": source.source_type},
    )
    await db.commit()
    return SourceCreated(
        id=source.id, name=source.name, source_type=source.source_type, shared_secret=secret
    )
