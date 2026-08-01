import asyncio
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from trustsoc.bootstrap import bootstrap
from trustsoc.config import get_settings
from trustsoc.logging import configure_logging
from trustsoc.routers import (
    assets,
    auth,
    blindness,
    health,
    honeypot,
    integrations,
    operations,
    overview,
    portal,
    reconstruction,
    rules,
    simulations,
    sources,
    telemetry,
)
from trustsoc.services.honeypot_sync import honeypot_sync_loop
from trustsoc.services.wazuh_sync import wazuh_sync_loop

settings = get_settings()
configure_logging(settings.log_level)
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await bootstrap()
    stop_event = asyncio.Event()
    sync_tasks: list[asyncio.Task] = []
    if settings.wazuh_enabled and settings.wazuh_sync_enabled:
        sync_tasks.append(asyncio.create_task(wazuh_sync_loop(stop_event), name="wazuh-sync-loop"))
    if settings.honeypot_enabled and settings.honeypot_sync_enabled:
        sync_tasks.append(
            asyncio.create_task(honeypot_sync_loop(stop_event), name="honeypot-sync-loop")
        )
    logger.info("trustsoc_started", environment=settings.env)
    yield
    stop_event.set()
    for sync_task in sync_tasks:
        try:
            await asyncio.wait_for(sync_task, timeout=10)
        except TimeoutError:
            sync_task.cancel()
    logger.info("trustsoc_stopped")


app = FastAPI(
    title="TRUST-SOC Enterprise API",
    version="0.4.0",
    description=(
        "Tamper-resilient multi-source telemetry assurance, alert correlation "
        "and incident response."
    ),
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    root_path="/api",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


@app.middleware("http")
async def security_and_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


for router in [
    health.router,
    auth.router,
    overview.router,
    portal.router,
    operations.router,
    assets.router,
    sources.router,
    telemetry.router,
    rules.router,
    blindness.router,
    reconstruction.router,
    simulations.router,
    integrations.router,
    honeypot.router,
]:
    app.include_router(router)
