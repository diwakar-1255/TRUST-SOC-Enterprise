from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.database import get_db
from trustsoc.dependencies import current_user, require_roles
from trustsoc.models import DetectionRule, User, UserRole
from trustsoc.schemas import RuleCreate, RuleOut

router = APIRouter(prefix="/rules", tags=["detection rules"])


@router.get("", response_model=list[RuleOut])
async def list_rules(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(
        select(DetectionRule)
        .where(DetectionRule.organization_id == user.organization_id)
        .order_by(DetectionRule.name)
    )
    return list(rows)


@router.post("", response_model=RuleOut, status_code=201)
async def create_rule(
    payload: RuleCreate,
    user: User = Depends(
        require_roles(UserRole.tenant_admin, UserRole.detection_engineer, UserRole.soc_manager)
    ),
    db: AsyncSession = Depends(get_db),
):
    duplicate = await db.scalar(
        select(DetectionRule).where(
            DetectionRule.organization_id == user.organization_id,
            DetectionRule.external_id == payload.external_id,
        )
    )
    if duplicate:
        raise HTTPException(409, "Rule external_id already exists")
    rule = DetectionRule(organization_id=user.organization_id, **payload.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule
