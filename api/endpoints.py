"""
PhishGuard-AI — API Endpoint Router.
======================================

Defines the ``/api/v1/analyse/semantics`` endpoint — the primary
ingestion point for the browser extension.  The handler orchestrates
the full analysis pipeline:

    DOM Payload → ETL Sanitization → [BERT Inference ∥ Mule Scan]
                                      (asyncio.gather)
               → Orchestration Verdict → JSON Response

Security: Protected by the ``verify_api_key`` dependency (Bearer token).
Concurrency: BERT inference and mule-account scanning execute **in
parallel** via ``asyncio.gather()`` to minimise wall-clock latency.

Architecture Layer : Presentation / API Gateway
Thesis Reference   : §6.1 — Request Orchestration & Parallel Execution
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Final

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from slowapi import Limiter  # type: ignore[import-untyped]
from slowapi.util import get_remote_address  # type: ignore[import-untyped]

from core.config import MALICIOUS_THRESHOLD, RATE_LIMIT, VERDICT_BLOCK, VERDICT_SAFE
from core.security import verify_api_key
from schemas.payload import WebPayload
from schemas.response import (
    AnalysisResponse,
    DataBlock,
    MetaBlock,
    MuleScanResult,
    SemanticResult,
)
from services.sanitizer import sanitize_dom
from database.repository import log_threat_telemetry

logger: Final[logging.Logger] = logging.getLogger("phishguard.endpoints")

# ==============================================================================
# Router Configuration
# ==============================================================================
router: Final[APIRouter] = APIRouter(
    prefix="/api/v1",
    tags=["Threat Analysis"],
    dependencies=[Depends(verify_api_key)],  # All routes require auth.
)

# ── Rate limiter instance (mirrors the one in main.py) ──
limiter: Final[Limiter] = Limiter(
    key_func=get_remote_address,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://",
)

# Maximum characters of sanitized text included in the response preview.
_PREVIEW_LENGTH: Final[int] = 200


# ==============================================================================
# POST /api/v1/analyse/semantics
# ==============================================================================

@router.post(
    "/analyse/semantics",
    response_model=AnalysisResponse,
    summary="Analyse a web page for phishing threats",
    description=(
        "Accepts a raw DOM payload, sanitises the HTML, runs BERT semantic "
        "analysis and mule-account scanning **in parallel**, and returns a "
        "unified threat-assessment response with an orchestration directive."
    ),
    response_description="Unified analysis envelope with orchestration verdict.",
    status_code=200,
)
@limiter.limit(RATE_LIMIT)
async def analyse_semantics(
    payload: WebPayload,
    request: Request,
    background_tasks: BackgroundTasks,
    _api_key: str = Depends(verify_api_key),
) -> AnalysisResponse:
    """Primary analysis endpoint invoked by the browser extension.

    Pipeline Steps
    --------------
    1. Generate a UUID v4 transaction identifier for traceability.
    2. ETL-sanitise the raw DOM content (strip tags, scripts, CSS).
    3. Start a high-resolution timer.
    4. Execute BERT inference and mule-account scanning **concurrently**
       via ``asyncio.gather()``.
    5. Determine the orchestration verdict based on combined results.
    6. If malicious, enqueue an async background task to persist
       telemetry (non-blocking — does not inflate response latency).
    7. Assemble and return the ``AnalysisResponse`` envelope.

    Parameters
    ----------
    payload : WebPayload
        Validated inbound request body.
    request : Request
        FastAPI request object — used to access ``app.state`` singletons.
    background_tasks : BackgroundTasks
        FastAPI background-task scheduler for deferred telemetry writes.
    _api_key : str
        The validated bearer token (unused in logic; satisfies the
        dependency chain for documentation purposes).

    Returns
    -------
    AnalysisResponse
        Nested JSON envelope with ``meta``, ``data``, and
        ``orchestration`` sections.
    """
    # asyncio imported at module level

    # ── 1. Transaction ID ──
    transaction_id: str = str(uuid.uuid4())
    logger.info(
        "[%s] Received analysis request for URL: %s",
        transaction_id,
        payload.url,
    )

    # ── 2. ETL Sanitisation ──
    sanitized_text: str = sanitize_dom(payload.dom_content)
    if not sanitized_text:
        logger.warning(
            "[%s] Sanitised text is empty — DOM may be purely structural.",
            transaction_id,
        )
        # Provide a fallback to prevent model errors on empty input.
        sanitized_text = "empty page content"

    logger.debug(
        "[%s] Sanitised text (%d chars): %s…",
        transaction_id,
        len(sanitized_text),
        sanitized_text[:100],
    )

    # ── 3. Retrieve singletons from app.state ──
    semantic_engine = request.app.state.semantic_engine
    mule_scanner = request.app.state.mule_scanner
    db = request.app.state.db

    # ── 4. Parallel Execution via asyncio.gather() ──
    #
    #   Both tasks are I/O-safe:
    #     • SemanticEngine.predict() delegates to asyncio.to_thread()
    #     • MuleScanner.scan_and_verify() uses async aiosqlite queries
    #
    start_ns: int = time.perf_counter_ns()

    bert_result: dict[str, Any]
    mule_result: dict[str, Any]

    bert_result, mule_result = await asyncio.gather(
        semantic_engine.predict(sanitized_text),
        mule_scanner.scan_and_verify(sanitized_text, db),
    )

    elapsed_ms: float = round(
        (time.perf_counter_ns() - start_ns) / 1_000_000, 2
    )

    logger.info(
        "[%s] Pipeline completed in %.2f ms — BERT=%s, Mule=%s",
        transaction_id,
        elapsed_ms,
        bert_result["label"],
        mule_result["mule_detected"],
    )

    # ── 5. Orchestration Verdict ──
    is_threat: bool = bert_result["is_malicious"] or mule_result["mule_detected"]
    verdict: str = VERDICT_BLOCK if is_threat else VERDICT_SAFE

    # ── 6. Background Telemetry (fire-and-forget) ──
    if bert_result["is_malicious"]:
        background_tasks.add_task(
            log_threat_telemetry,
            url=str(payload.url),
            score=bert_result["confidence"],
            db=db,
        )
        logger.info(
            "[%s] Telemetry write scheduled (background).",
            transaction_id,
        )

    # ── 7. Assemble Response ──
    response = AnalysisResponse(
        meta=MetaBlock(
            transaction_id=transaction_id,
            processing_time_ms=elapsed_ms,
        ),
        data=DataBlock(
            semantic_analysis=SemanticResult(
                label=bert_result["label"],
                confidence=bert_result["confidence"],
                is_malicious=bert_result["is_malicious"],
                sanitized_text_preview=sanitized_text[:_PREVIEW_LENGTH],
            ),
            mule_scan=MuleScanResult(
                accounts_extracted=mule_result["accounts_extracted"],
                flagged_accounts=mule_result["flagged_accounts"],
                mule_detected=mule_result["mule_detected"],
            ),
        ),
        orchestration=verdict,
    )

    logger.info(
        "[%s] Response assembled — verdict=%s",
        transaction_id,
        verdict,
    )

    return response
