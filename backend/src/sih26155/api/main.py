from contextlib import asynccontextmanager
import logging
import os
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sih26155.api.middleware.rate_limit import SlidingWindowRateLimiter
from sih26155.api.routes.analysis import router as analysis_router
from sih26155.api.routes.history import router as history_router
from sih26155.api.routes.intelligence import router as intelligence_router
from sih26155.api.routes.learning import router as learning_router
from sih26155.api.routes.live import router as live_router
from sih26155.api.routes.network_audit import router as network_audit_router
from sih26155.api.routes.remediation import router as remediation_router
from sih26155.api.routes.reports import router as reports_router
from sih26155.core.logging import setup_logging
from sih26155.storage.database import check_db_health, create_all_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create all database tables on startup (idempotent) and setup structured logging."""
    setup_logging()
    logger = logging.getLogger("sih26155.api")
    try:
        create_all_tables()
        logger.info("Database schemas verified and initialized.")
    except Exception as exc:
        logger.critical("Database initialization failed during startup: %s", exc, exc_info=True)
    yield


app = FastAPI(
    title="SIH AI Compliance Engine",
    version="0.1.0",
    lifespan=lifespan,
)

# Configurable environment-aware CORS policy (Drawback 1)
allowed_origins_env = os.getenv("ALLOWED_ORIGINS")
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

is_wildcard = "*" in allowed_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if not is_wildcard else ["*"],
    allow_credentials=not is_wildcard,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sliding window rate limiting to protect scanning & live remediation endpoints (Drawback 20)
app.add_middleware(SlidingWindowRateLimiter)

app.include_router(analysis_router)
app.include_router(live_router)
app.include_router(network_audit_router)
app.include_router(remediation_router)
app.include_router(intelligence_router)
app.include_router(learning_router)
app.include_router(history_router)
app.include_router(reports_router)


@app.get("/health")
def health() -> dict[str, str]:
    db_healthy = check_db_health()
    return {"status": "ok" if db_healthy else "degraded"}
