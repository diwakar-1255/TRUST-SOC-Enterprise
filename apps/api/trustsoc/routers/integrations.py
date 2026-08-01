from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.config import get_settings
from trustsoc.database import get_db
from trustsoc.dependencies import current_user, require_roles
from trustsoc.integrations.honeypot import HoneypotClient
from trustsoc.integrations.wazuh import WazuhClient, WazuhIndexerClient
from trustsoc.models import IntegrationState, User, UserRole
from trustsoc.schemas import HoneypotIntegrationStatusOut, IntegrationStatusOut
from trustsoc.services.honeypot_sync import _status_payload as honeypot_status_payload
from trustsoc.services.honeypot_sync import sync_honeypot
from trustsoc.services.wazuh_sync import sync_wazuh

router = APIRouter(prefix="/integrations", tags=["integrations"])


def _status_payload(settings, state: IntegrationState | None) -> IntegrationStatusOut:
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


@router.get("/wazuh/health")
async def wazuh_health(user: User = Depends(current_user)):
    settings = get_settings()
    if not settings.wazuh_enabled:
        return {"enabled": False, "status": "disabled"}
    try:
        manager, indexer = await WazuhClient().health(), await WazuhIndexerClient().health()
        return {
            "enabled": True,
            "status": "connected",
            "manager": manager,
            "indexer": indexer,
        }
    except Exception as exc:
        raise HTTPException(502, f"Wazuh integration failed: {type(exc).__name__}") from exc


@router.get("/wazuh/status", response_model=IntegrationStatusOut)
async def wazuh_status(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    state = await db.scalar(
        select(IntegrationState).where(
            IntegrationState.organization_id == user.organization_id,
            IntegrationState.integration == "wazuh",
        )
    )
    return _status_payload(settings, state)


@router.post("/wazuh/sync")
async def synchronize_wazuh(
    user: User = Depends(
        require_roles(UserRole.tenant_admin, UserRole.soc_manager, UserRole.soc_analyst)
    ),
):
    settings = get_settings()
    if not settings.wazuh_enabled:
        raise HTTPException(409, "Wazuh integration is disabled")
    try:
        return await sync_wazuh(user.organization_id)
    except Exception as exc:
        raise HTTPException(502, f"Wazuh synchronization failed: {type(exc).__name__}") from exc


@router.get("/honeypot/health")
async def honeypot_health(user: User = Depends(current_user)):
    settings = get_settings()
    if not settings.honeypot_enabled:
        return {"enabled": False, "status": "disabled"}
    try:
        client = HoneypotClient()
        health, stats = await client.health(), await client.stats()
        return {"enabled": True, "status": "connected", "health": health, "stats": stats}
    except Exception as exc:
        raise HTTPException(502, f"Honeypot integration failed: {type(exc).__name__}") from exc


@router.get("/honeypot/status", response_model=HoneypotIntegrationStatusOut)
async def honeypot_status(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    state = await db.scalar(
        select(IntegrationState).where(
            IntegrationState.organization_id == user.organization_id,
            IntegrationState.integration == "honeypot",
        )
    )
    return HoneypotIntegrationStatusOut(**honeypot_status_payload(state))


@router.post("/honeypot/sync")
async def synchronize_honeypot(
    user: User = Depends(
        require_roles(UserRole.tenant_admin, UserRole.soc_manager, UserRole.soc_analyst)
    ),
):
    settings = get_settings()
    if not settings.honeypot_enabled:
        raise HTTPException(409, "Honeypot integration is disabled")
    try:
        return await sync_honeypot(user.organization_id)
    except Exception as exc:
        raise HTTPException(502, f"Honeypot synchronization failed: {type(exc).__name__}") from exc
