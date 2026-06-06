"""
PhishGuard-AI — Application Configuration Module.
==================================================

Centralizes all runtime constants, feature flags, and environment-driven
configuration values.  Follows the Twelve-Factor App methodology by
preferring environment variables with sensible defaults.

Architecture Layer: Core / Cross-Cutting Concerns
Thesis Reference : §3.1 — System Configuration & Operational Parameters
"""

from __future__ import annotations

import os
from typing import Final


# ==============================================================================
# 1. APPLICATION METADATA
# ==============================================================================
APP_TITLE: Final[str] = "PhishGuard-AI"
APP_DESCRIPTION: Final[str] = (
    "Enterprise-grade, real-time Anti-Phishing Browser Security Suite. "
    "Performs semantic NLP analysis and mule-account scanning on raw DOM payloads."
)
APP_VERSION: Final[str] = "1.0.0"

# ==============================================================================
# 2. SECURITY CONSTANTS
# ==============================================================================
# The bearer token expected in the Authorization header.
# In production this MUST be injected via a secrets manager (e.g., HashiCorp
# Vault, AWS Secrets Manager) — **never** hard-coded.
API_SECRET_TOKEN: Final[str] = os.getenv(
    "PHISHGUARD_API_KEY",
    "phishguard_secret_key_2026",
)

# ==============================================================================
# 3. RATE LIMITING
# ==============================================================================
# Maximum requests per minute per client IP.  Enforced by SlowAPI.
RATE_LIMIT: Final[str] = os.getenv("PHISHGUARD_RATE_LIMIT", "10/minute")

# ==============================================================================
# 4. DATABASE
# ==============================================================================
# Relative path for the aiosqlite database file.
DATABASE_PATH: Final[str] = os.getenv(
    "PHISHGUARD_DB_PATH",
    "phishguard.db",
)

# ==============================================================================
# 5. ML / NLP ENGINE
# ==============================================================================
# Hugging Face model identifier — used during the lifespan cold-start.
# `textattack/bert-base-uncased-SST-2` is a fine-tuned BERT for sentiment
# analysis and serves as a placeholder for a production phishing classifier.
BERT_MODEL_NAME: Final[str] = os.getenv(
    "PHISHGUARD_BERT_MODEL",
    "./phishguard_custom_model",
)

# Confidence threshold above which a DOM payload is flagged as malicious.
# SST-2 label 0 = "negative" (mapped to phishing) at this threshold.
MALICIOUS_THRESHOLD: Final[float] = float(
    os.getenv("PHISHGUARD_MALICIOUS_THRESHOLD", "0.75")
)

# ==============================================================================
# 6. MULE SCANNER
# ==============================================================================
# Regex pattern matching 10–14 digit Malaysian bank account numbers.
MULE_ACCOUNT_REGEX: Final[str] = r"\b\d{10,14}\b"

# ==============================================================================
# 7. ORCHESTRATION VERDICTS
# ==============================================================================
VERDICT_BLOCK: Final[str] = "BLOCK_RENDER"
VERDICT_SAFE: Final[str] = "SAFE"
