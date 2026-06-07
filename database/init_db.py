"""
PhishGuard-AI — Database Initialization Module.
=================================================

Responsible for DDL execution (table creation) and seed-data insertion
during the application's ``lifespan`` cold-start.  All tables conform to
Third Normal Form (3NF) as mandated by the thesis.

Architecture Layer : Data-Access / Repository (Infrastructure)
Thesis Reference   : §5.1 — Persistence Schema Design (3NF)

Tables
------
``mule_registry``
    Stores known mule (money-mule) bank accounts reported across
    Malaysian financial institutions.

``threat_telemetry``
    Append-only log of every malicious URL detected by the BERT pipeline,
    used for post-incident forensics and threat-intelligence dashboards.
"""

from __future__ import annotations

import logging
from typing import Final

import aiosqlite

from core.config import DATABASE_PATH

logger: Final[logging.Logger] = logging.getLogger("phishguard.database")

# ==============================================================================
# DDL — Table Definitions (3NF)
# ==============================================================================

_DDL_MULE_REGISTRY: Final[str] = """
CREATE TABLE IF NOT EXISTS mule_registry (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number   TEXT    NOT NULL UNIQUE,
    bank_name        TEXT    NOT NULL,
    platform_flagged TEXT    NOT NULL DEFAULT 'manual_entry',
    report_count     INTEGER NOT NULL DEFAULT 1 CHECK (report_count >= 0),
    date_added       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

_DDL_THREAT_TELEMETRY: Final[str] = """
CREATE TABLE IF NOT EXISTS threat_telemetry (
    log_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    malicious_url TEXT    NOT NULL,
    bert_score    REAL   NOT NULL CHECK (bert_score >= 0.0 AND bert_score <= 1.0),
    timestamp     TEXT   NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

# ── Explicit B-Tree Indexes (§4.4) ──
# SQLite's UNIQUE constraint on account_number creates an implicit index,
# but we declare it explicitly for clarity and to align with the thesis.
# The malicious_url index accelerates threat-intelligence lookups.
_IDX_MULE_ACCOUNT: Final[str] = """
CREATE INDEX IF NOT EXISTS idx_mule_account_number
    ON mule_registry (account_number);
"""

_IDX_TELEMETRY_URL: Final[str] = """
CREATE INDEX IF NOT EXISTS idx_telemetry_malicious_url
    ON threat_telemetry (malicious_url);
"""

# ==============================================================================
# Seed Data — Dummy Scammer Accounts
# ==============================================================================
# Three fictitious mule accounts pre-loaded for development & integration
# testing.  Real-world data would be ingested from PDRM / BNM feeds.
_SEED_MULE_ACCOUNTS: Final[list[tuple[str, str, str, int]]] = [
    ("1234567890",   "Maybank",       "Shopee",       14),
    ("9876543210",   "CIMB Bank",     "WhatsApp",      7),
    ("11223344556",  "Public Bank",   "Telegram",      3),
]

_INSERT_SEED: Final[str] = """
INSERT OR IGNORE INTO mule_registry
    (account_number, bank_name, platform_flagged, report_count)
VALUES
    (?, ?, ?, ?);
"""


# ==============================================================================
# Public API
# ==============================================================================

async def initialize_database() -> aiosqlite.Connection:
    """Create (or open) the SQLite database, execute DDL, and seed data.

    This coroutine is designed to be invoked **once** inside the FastAPI
    ``lifespan`` context manager.  The returned connection is stored in
    ``app.state`` and shared across request handlers via dependency
    injection.

    Returns
    -------
    aiosqlite.Connection
        A long-lived, WAL-mode connection to the PhishGuard database.
    """
    logger.info("Initializing database at '%s' …", DATABASE_PATH)

    db: aiosqlite.Connection = await aiosqlite.connect(DATABASE_PATH)

    # ── Enable WAL mode for concurrent readers + single writer ──
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA foreign_keys=ON;")

    # ── DDL: Create tables idempotently ──
    await db.execute(_DDL_MULE_REGISTRY)
    await db.execute(_DDL_THREAT_TELEMETRY)

    # ── Create B-Tree indexes for O(log N) lookups (§4.4) ──
    await db.execute(_IDX_MULE_ACCOUNT)
    await db.execute(_IDX_TELEMETRY_URL)

    # ── Seed: Insert dummy mule accounts (ignored on conflict) ──
    for account in _SEED_MULE_ACCOUNTS:
        await db.execute(_INSERT_SEED, account)

    await db.commit()

    logger.info(
        "Database ready — %d seed mule accounts loaded.",
        len(_SEED_MULE_ACCOUNTS),
    )
    return db
