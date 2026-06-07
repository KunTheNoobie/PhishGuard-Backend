"""
PhishGuard-AI — Security & Authentication Module.
===================================================

Implements the API-key bearer-token authentication dependency consumed by
protected FastAPI route handlers via ``Depends(verify_api_key)``.

Architecture Layer : Cross-Cutting / Middleware
Security Model    : Static Bearer Token (upgradeable to JWT / OAuth 2.0)
Thesis Reference  : §4.3 — API Gateway Security Controls
"""

from __future__ import annotations

import hmac
from typing import Final

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.config import API_SECRET_TOKEN

# ---------------------------------------------------------------------------
# HTTP Bearer scheme — FastAPI will extract the token from the
# ``Authorization: Bearer <token>`` header automatically and surface it as
# an ``HTTPAuthorizationCredentials`` instance.
# ---------------------------------------------------------------------------
_bearer_scheme: Final[HTTPBearer] = HTTPBearer(
    scheme_name="PhishGuard API Key",
    description="Provide your PhishGuard API key as a Bearer token.",
    auto_error=True,  # Returns 403 if header is missing entirely.
)


async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> str:
    """FastAPI dependency that validates the incoming bearer token.

    Designed for injection via ``Depends(verify_api_key)`` on any router
    or individual endpoint that requires authentication.

    Uses ``hmac.compare_digest()`` to perform a constant-time comparison,
    mitigating timing side-channel attacks that could leak the secret
    length or character positions.

    Parameters
    ----------
    credentials : HTTPAuthorizationCredentials
        Automatically populated by the ``HTTPBearer`` scheme from the
        ``Authorization`` header.

    Returns
    -------
    str
        The validated API key (useful for downstream audit logging).

    Raises
    ------
    HTTPException (401)
        If the token does not match the configured secret.
    """
    # ── Constant-time comparison to prevent timing side-channel attacks ──
    if not hmac.compare_digest(credentials.credentials, API_SECRET_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_API_KEY",
                "message": (
                    "The provided bearer token is invalid or has been "
                    "revoked.  Contact your PhishGuard administrator."
                ),
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
