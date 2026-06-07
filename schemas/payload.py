"""
PhishGuard-AI — Request Payload Schemas.
=========================================

Pydantic v2 models defining the shape of incoming request bodies.  Every
field carries explicit type annotations (PEP 484) and validator metadata
so that FastAPI can auto-generate OpenAPI documentation and perform
server-side validation *before* any business logic executes.

Architecture Layer: DTO / Anti-Corruption Layer
Thesis Reference : §3.4 — Inbound Data Contracts
"""

from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl


class WebPayload(BaseModel):
    """Canonical inbound payload for the ``/analyse/semantics`` endpoint.

    Attributes
    ----------
    url : HttpUrl
        The fully-qualified URL of the page currently rendered in the
        user's browser.  Validated to reject malformed URIs at the edge.
    dom_content : str
        The raw ``document.documentElement.outerHTML`` captured by the
        browser extension.  Will be ETL-sanitised before NLP inference.
    """

    url: HttpUrl = Field(
        ...,
        title="Page URL",
        description="Fully-qualified URL of the inspected page.",
        examples=["https://secure-banking.example.com/login"],
    )
    dom_content: str = Field(
        ...,
        title="Raw DOM Content",
        description=(
            "Complete outerHTML of the page.  Must contain at least one "
            "non-whitespace character after sanitization."
        ),
        min_length=1,
        max_length=5_000_000,  # 5 MB hard cap to prevent DoS.
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "url": "https://maybank2u.com.my/login",
                    "dom_content": (
                        "<html><body><h1>Login</h1>"
                        "<p>Please transfer RM500 to account 1234567890</p>"
                        "</body></html>"
                    ),
                }
            ]
        }
    }
