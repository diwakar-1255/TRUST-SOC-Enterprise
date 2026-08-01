from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.audit import write_audit
from trustsoc.database import get_db
from trustsoc.dependencies import current_user, require_roles
from trustsoc.models import Asset, User, UserRole
from trustsoc.schemas import AssetCreate, AssetOut

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
async def list_assets(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    result = await db.scalars(
        select(Asset).where(Asset.organization_id == user.organization_id).order_by(Asset.hostname)
    )
    return list(result)


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(
    payload: AssetCreate,
    user: User = Depends(require_roles(UserRole.tenant_admin, UserRole.soc_manager)),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.scalar(
        select(Asset).where(
            Asset.organization_id == user.organization_id, Asset.hostname == payload.hostname
        )
    )
    if existing:
        raise HTTPException(409, "Asset already exists")
    asset = Asset(organization_id=user.organization_id, **payload.model_dump())
    db.add(asset)
    await db.flush()
    await write_audit(
        db,
        action="asset.create",
        resource_type="asset",
        resource_id=str(asset.id),
        organization_id=user.organization_id,
        actor_id=user.id,
    )
    await db.commit()
    await db.refresh(asset)
    return asset
