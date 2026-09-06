"""
AI Autonomous Pentest Platform — FastAPI Application Entry Point
"""
import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import os

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.database import engine, Base
from app.api.v1 import router as api_v1_router
from app.api.websocket import router as ws_router
from app.services.bootstrap import bootstrap_admin_user

import app.models_microseg  # Register microsegmentation tables
import app.models_xdr        # Register MorfeuXDR tables
import app.models_honeypot   # Register Honeypot & Grafana Correlation tables

setup_logging()
logger = structlog.get_logger(__name__)

# ─── Prometheus Metrics ───────────────────────────────────────────────────────
REQUEST_COUNT = Counter("api_requests_total", "Total API requests", ["method", "endpoint", "status"])
REQUEST_LATENCY = Histogram("api_request_duration_seconds", "API request duration", ["method", "endpoint"])
FINDINGS_TOTAL = Counter("findings_total", "Total findings created", ["severity"])
SCREENSHOTS_TOTAL = Counter("screenshots_total", "Total screenshots captured")
REPORTS_GENERATED = Counter("reports_generated", "Total reports generated", ["report_type"])
PENTEST_JOBS = Counter("pentest_jobs_total", "Total pentest jobs started")
PENTEST_RUNNING = Counter("pentest_jobs_running", "Currently running pentest jobs")


# ─── Lifespan ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "🚀 AI Autonomous Pentest Platform starting",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        llm_provider=settings.LLM_PROVIDER,
    )

    # Create data directories
    os.makedirs(settings.SCREENSHOTS_DIR, exist_ok=True)
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)

    # Create DB tables
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        logger.warning("Could not auto-create DB tables", error=str(e))

    # Bootstrap admin user on first run
    await bootstrap_admin_user()

    logger.info("✅ Platform ready", docs_url="http://localhost:8000/docs")
    yield

    logger.info("🛑 Platform shutting down")


# ─── App Factory ─────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
## AI Autonomous Pentest Platform

Professional pentest automation platform for authorized Red Team operations.

### Safety Controls
- **Scope Enforcement**: All targets validated against authorized allowlist
- **Kill Switch**: Immediate termination of all active tests
- **Audit Log**: All actions recorded and immutable
- **Safe Defaults**: Passive mode enabled by default

### Modes
- `PASSIVE` — Discovery only, no active testing
- `SAFE_ACTIVE` — Non-destructive active testing
- `AUTHORIZED_ADVERSARY` — Full testing within authorized scope
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ─── Middleware ───────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count", "X-Request-ID"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    """Prometheus metrics + request ID + structured logging."""
    start_time = time.time()
    request_id = request.headers.get("X-Request-ID", f"req_{int(start_time * 1000)}")

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )

    response = await call_next(request)

    duration = time.time() - start_time
    endpoint = request.url.path.split("?")[0]

    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=endpoint,
        status=response.status_code,
    ).inc()
    REQUEST_LATENCY.labels(method=request.method, endpoint=endpoint).observe(duration)

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{duration:.3f}s"

    # Enhanced Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"

    return response


# ─── Routes ──────────────────────────────────────────────────────────────────
app.include_router(api_v1_router, prefix="/api/v1")
app.include_router(ws_router)


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "llm_enabled": settings.llm_enabled,
    }


@app.get("/metrics", tags=["System"])
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", error=str(exc), path=request.url.path, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request.headers.get("X-Request-ID")},
    )
