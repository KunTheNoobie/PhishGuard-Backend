"""
PhishGuard-AI — Response Envelope Schemas.
===========================================

Defines the unified JSON response structure returned by all analysis
endpoints.  The envelope follows the **JSend** convention extended with
an ``orchestration`` directive consumed by the browser extension's
content-script to decide whether to block page rendering.

Architecture Layer : DTO / Presentation
Thesis Reference   : §3.5 — Outbound Data Contracts & Orchestration Signals

Response Shape
--------------
.. code-block:: json

    {
        "meta": {
            "transaction_id": "uuid4",
            "processing_time_ms": 142.7
        },
        "data": {
            "semantic_analysis": { ... },
            "mule_scan": { ... }
        },
        "orchestration": "BLOCK_RENDER | SAFE"
    }
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ==============================================================================
# Sub-Models
# ==============================================================================

class MetaBlock(BaseModel):
    """Operational metadata attached to every API response."""

    transaction_id: str = Field(
        ...,
        description="UUID v4 uniquely identifying this analysis transaction.",
    )
    processing_time_ms: float = Field(
        ...,
        description="Wall-clock latency of the full analysis pipeline in ms.",
    )


class SemanticResult(BaseModel):
    """Output of the BERT-based semantic analysis stage."""

    label: str = Field(
        ...,
        description=(
            "Classification label emitted by the NLP model "
            "(e.g., 'PHISHING', 'LEGITIMATE')."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Softmax confidence score in [0, 1].",
    )
    is_malicious: bool = Field(
        ...,
        description="True if confidence exceeds the malicious threshold.",
    )
    sanitized_text_preview: str = Field(
        ...,
        description="Truncated preview of the sanitized text fed to BERT.",
    )


class MuleScanResult(BaseModel):
    """Output of the mule-account scanning stage."""

    accounts_extracted: list[str] = Field(
        default_factory=list,
        description="Account numbers extracted from the page via regex.",
    )
    flagged_accounts: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Subset of extracted accounts that matched known mule records "
            "in the registry, including bank name and report count."
        ),
    )
    mule_detected: bool = Field(
        ...,
        description="True if at least one flagged mule account was found.",
    )


class DataBlock(BaseModel):
    """Aggregated analysis results from all pipeline stages."""

    semantic_analysis: SemanticResult
    mule_scan: MuleScanResult


# ==============================================================================
# Top-Level Envelope
# ==============================================================================

class AnalysisResponse(BaseModel):
    """Unified response envelope for the ``/analyse/semantics`` endpoint.

    The ``orchestration`` field carries a directive that the browser
    extension's content-script interprets:

    - ``BLOCK_RENDER`` — inject a warning interstitial and prevent the
      page from rendering.
    - ``SAFE`` — allow normal rendering; no action required.
    """

    meta: MetaBlock
    data: DataBlock
    orchestration: str = Field(
        ...,
        description="Orchestration directive: 'BLOCK_RENDER' or 'SAFE'.",
        examples=["BLOCK_RENDER", "SAFE"],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "meta": {
                        "transaction_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                        "processing_time_ms": 142.7,
                    },
                    "data": {
                        "semantic_analysis": {
                            "label": "PHISHING",
                            "confidence": 0.97,
                            "is_malicious": True,
                            "sanitized_text_preview": "Please transfer RM500 to ...",
                        },
                        "mule_scan": {
                            "accounts_extracted": ["1234567890"],
                            "flagged_accounts": [
                                {
                                    "account_number": "1234567890",
                                    "bank_name": "Maybank",
                                    "report_count": 14,
                                }
                            ],
                            "mule_detected": True,
                        },
                    },
                    "orchestration": "BLOCK_RENDER",
                }
            ]
        }
    }
