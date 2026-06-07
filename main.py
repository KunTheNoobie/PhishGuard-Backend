"""
PhishGuard-AI — Application Entry Point.
==========================================

Bootstraps the FastAPI application with:

    1. **Lifespan Context Manager** — cold-starts the BERT model
       (Singleton), the Mule Scanner (pre-compiled regex), and the
       aiosqlite database connection.  All three are stored in
       ``app.state`` and shared across requests via dependency injection.
       On shutdown, resources are explicitly released.

    2. **Rate Limiting** — enforced globally via ``SlowAPI`` using the
       client's IP address as the rate-limit key.

    3. **Router Inclusion** — mounts the ``/api/v1`` analysis router.

    4. **Structured Logging** — configures a uniform log format across
       all PhishGuard modules.

Run with:
    ``uvicorn main:app --host 0.0.0.0 --port 8000 --reload``

Architecture Layer : Composition Root / Application Shell
Thesis Reference   : §6.2 — Application Bootstrap & Lifespan Management
"""

from __future__ import annotations

import logging
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Final

import torch
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore[import-untyped]
from slowapi.errors import RateLimitExceeded  # type: ignore[import-untyped]
from slowapi.util import get_remote_address  # type: ignore[import-untyped]
from starlette.middleware.base import BaseHTTPMiddleware

from api.endpoints import router as analysis_router
from core.config import (
    APP_DESCRIPTION,
    APP_TITLE,
    APP_VERSION,
    RATE_LIMIT,
)
from database.init_db import initialize_database
from services.mule_scanner import MuleScanner
from services.nlp_engine import SemanticEngine

# ==============================================================================
# Logging Configuration
# ==============================================================================
_LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
)

logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
    force=True,
)

logger: Final[logging.Logger] = logging.getLogger("phishguard.main")

# ==============================================================================
# Rate Limiter (SlowAPI)
# ==============================================================================
limiter: Final[Limiter] = Limiter(
    key_func=get_remote_address,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://",
)


# ==============================================================================
# Lifespan Context Manager (PEP 3143-style)
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application-wide singletons across the server lifecycle.

    **Startup Phase** (before ``yield``):
        1. Initialise the aiosqlite database (DDL + seed data).
        2. Instantiate the ``SemanticEngine`` (loads BERT into memory).
        3. Run a warm-up inference pass to prime caches.
        4. Instantiate the ``MuleScanner`` (compiles the regex).
        5. Store all singletons in ``app.state``.

    **Shutdown Phase** (after ``yield``):
        1. Shut down the ``SemanticEngine`` (frees GPU VRAM).
        2. Close the aiosqlite connection.
        3. Log a clean-shutdown confirmation.

    Yields
    ------
    None
        Control is returned to the ASGI server for the duration of the
        application's runtime.
    """
    # ────────────────────── STARTUP ──────────────────────
    logger.info("=" * 60)
    logger.info("  PhishGuard-AI Backend — Starting Up")
    logger.info("=" * 60)

    # 1. Database
    logger.info("[1/4] Initialising database …")
    app.state.db = await initialize_database()

    # 2. BERT Semantic Engine (Singleton)
    logger.info("[2/4] Loading BERT Semantic Engine …")
    engine = SemanticEngine()
    app.state.semantic_engine = engine

    # 3. Warm-up pass
    logger.info("[3/4] Running BERT warm-up inference …")
    engine.warm_up()

    # 4. Mule Scanner
    logger.info("[4/4] Initialising Mule Scanner …")
    app.state.mule_scanner = MuleScanner()

    logger.info("=" * 60)
    logger.info("  PhishGuard-AI Backend — Ready to Serve")
    logger.info("=" * 60)

    yield  # ← Application is running and accepting requests.

    # ────────────────────── SHUTDOWN ──────────────────────
    logger.info("=" * 60)
    logger.info("  PhishGuard-AI Backend — Shutting Down")
    logger.info("=" * 60)

    # Release ML resources
    app.state.semantic_engine.shutdown()

    # Close database connection
    await app.state.db.close()

    logger.info("All resources released.  Goodbye.")


# ==============================================================================
# FastAPI Application Instance
# ==============================================================================

app: Final[FastAPI] = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={
        "name": "PhishGuard-AI Security Team",
        "email": "security@phishguard.ai",
    },
    license_info={
        "name": "Proprietary",
        "identifier": "LicenseRef-PhishGuard-Proprietary",
    },
)

# ── Attach the rate limiter to the app ──
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Global Exception Handler: PyTorch / CUDA Inference Errors (§4.5) ──
@app.exception_handler(RuntimeError)
async def pytorch_runtime_error_handler(
    request: Request, exc: RuntimeError
) -> JSONResponse:
    """Catch PyTorch/CUDA RuntimeErrors (e.g., OOM) and return a
    structured 503 response instead of a raw 500."""
    error_msg = str(exc).lower()
    if "cuda" in error_msg or "out of memory" in error_msg:
        logger.critical("CUDA Out-of-Memory during inference: %s", exc)
        # Attempt to free cached GPU memory
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        return JSONResponse(
            status_code=503,
            content={
                "error": "MODEL_INFERENCE_FAILURE",
                "message": (
                    "The AI inference engine encountered a memory allocation "
                    "failure.  Please retry the request or contact your "
                    "PhishGuard administrator."
                ),
            },
        )
    # Re-raise non-CUDA RuntimeErrors to the default handler
    raise exc


# ── CORS Middleware (restrict in production) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict to extension origin in prod.
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Request Logging Middleware ──
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs the method, path, status code, and latency of every request."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter_ns()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter_ns() - start) / 1_000_000, 2)
        logger.info(
            "%s %s → %d (%.2f ms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response


app.add_middleware(RequestLoggingMiddleware)


# ── Mount the API router ──
app.include_router(analysis_router)


# ==============================================================================
# Health Check (unprotected)
# ==============================================================================

@app.get(
    "/health",
    tags=["Operations"],
    summary="Liveness probe",
    response_description="Service health status.",
)
async def health_check() -> dict[str, str]:
    """Lightweight liveness probe for orchestrators (K8s, ECS, etc.)."""
    return {"status": "healthy", "service": APP_TITLE, "version": APP_VERSION}


# ==============================================================================
# Uvicorn Direct Execution
# ==============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
