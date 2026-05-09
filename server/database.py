"""
server/database.py — Async SQLite via aiosqlite
=================================================

Tables
------
  users     — registered users + ML-DSA-65 and ML-KEM-768 public keys
  sessions  — KEM session references (no secrets ever stored)
  messages  — persistent chat message log
  transfers — file transfer metadata only (NO file bytes ever stored)

Rules
-----
  - Session shared secrets are NEVER stored anywhere — ephemeral, client-only
  - File bytes are NEVER stored — server is pure relay
  - All DB ops are async — non-blocking with FastAPI asyncio event loop
"""

import aiosqlite
import os
import logging

logger  = logging.getLogger("pqc_chat.db")
DB_PATH = os.getenv("DB_PATH", "chat.db")


#  Schema 

async def init_db():
    """
    Create all tables and indexes on startup.
    Safe to call every run — IF NOT EXISTS prevents data loss.
    """
    logger.info(f"  [DB] Initialising SQLite at: {DB_PATH}")
    async with aiosqlite.connect(DB_PATH) as db:

        # users: one row per registered username
        # dsa_public_key : ML-DSA-65 pk — peers use this to verify signatures
        # kem_public_key : ML-KEM-768 pk — peers use this to encapsulate shared secrets
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username       TEXT PRIMARY KEY,
                dsa_public_key BLOB NOT NULL,
                kem_public_key BLOB NOT NULL,
                created_at     TEXT DEFAULT (datetime('now'))
            )
        """)

        # sessions: records that a KEM session was established between two users
        # No shared secrets stored — those live only in client memory
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                user_a         TEXT NOT NULL,
                user_b         TEXT NOT NULL,
                kem_ciphertext BLOB,
                created_at     TEXT DEFAULT (datetime('now')),
                UNIQUE(user_a, user_b)
            )
        """)

        # messages: full chat log
        # content    : plaintext body (sender includes it in envelope for server logging)
        # delivered  : 0 = not delivered live, 1 = delivered to recipient's socket
        # delivered_at: timestamp when delivery confirmed
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                sender       TEXT NOT NULL,
                recipient    TEXT NOT NULL,
                content      TEXT NOT NULL,
                delivered    INTEGER NOT NULL DEFAULT 0,
                sent_at      TEXT DEFAULT (datetime('now')),
                delivered_at TEXT
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_pair
            ON messages (sender, recipient)
        """)

        # transfers: file transfer metadata only — NO file bytes ever here
        # transfer_id : UUID from sender client — unique per attempt
        # disk_needed : bytes receiver must have free (filesize + 10% buffer)
        # status lifecycle:
        #   offered  transferring  completed
        #                         ↘ rejected   (receiver declined)
        #                         ↘ aborted    (disconnect / cancel)
        #                         ↘ failed     (network error mid-transfer)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS transfers (
                transfer_id  TEXT PRIMARY KEY,
                sender       TEXT NOT NULL,
                receiver     TEXT NOT NULL,
                filename     TEXT NOT NULL,
                filesize     INTEGER NOT NULL,
                disk_needed  INTEGER NOT NULL DEFAULT 0,
                status       TEXT NOT NULL DEFAULT 'offered',
                started_at   TEXT DEFAULT (datetime('now')),
                completed_at TEXT
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_transfers_sender
            ON transfers (sender)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_transfers_receiver
            ON transfers (receiver)
        """)

        await db.commit()
    logger.info(" [DB] Tables ready: users / sessions / messages / transfers")


#  User helpers 

async def register_user(username: str, dsa_pk: bytes, kem_pk: bytes) -> bool:
    """
    Insert or replace user record with PQC public keys.
    INSERT OR REPLACE means re-connecting clients update their keys.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR REPLACE INTO users (username, dsa_public_key, kem_public_key) VALUES (?, ?, ?)",
                (username, dsa_pk, kem_pk),
            )
            await db.commit()
        logger.info(f" [DB] Registered '{username}' dsa={len(dsa_pk)}B kem={len(kem_pk)}B")
        return True
    except Exception as e:
        logger.error(f" [DB] register_user failed: {e}")
        return False


async def get_user(username: str) -> dict | None:
    """Fetch user record with both public keys. Returns None if not found."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT username, dsa_public_key, kem_public_key FROM users WHERE username=?",
            (username,),
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def user_exists(username: str) -> bool:
    """True if username has ever registered (in DB). Not same as currently online."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ) as cur:
            return await cur.fetchone() is not None


#  Chat message helpers 

async def save_message(
    sender: str, recipient: str, content: str, delivered: bool = False
) -> int | None:
    """
    Persist one chat message. Returns row id (used to mark delivered later).
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "INSERT INTO messages (sender, recipient, content, delivered) VALUES (?, ?, ?, ?)",
                (sender, recipient, content, int(delivered)),
            )
            await db.commit()
            row_id = cur.lastrowid
        logger.info(f" [DB] msg id={row_id} '{sender}''{recipient}' delivered={delivered}")
        return row_id
    except Exception as e:
        logger.error(f" [DB] save_message failed: {e}")
        return None


async def mark_message_delivered(row_id: int):
    """Flip delivered=1 and stamp delivered_at after successful live relay."""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE messages SET delivered=1, delivered_at=datetime('now') WHERE id=?",
                (row_id,),
            )
            await db.commit()
        logger.info(f" [DB] msg id={row_id}  delivered=1")
    except Exception as e:
        logger.error(f" [DB] mark_message_delivered failed: {e}")


async def get_conversation(user_a: str, user_b: str, limit: int = 100) -> list[dict]:
    """Messages between two users, both directions, oldest-first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, sender, recipient, content, delivered, sent_at, delivered_at
            FROM   messages
            WHERE  (sender=? AND recipient=?) OR (sender=? AND recipient=?)
            ORDER  BY id ASC LIMIT ?
            """,
            (user_a, user_b, user_b, user_a, limit),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_user_messages(username: str, limit: int = 200) -> list[dict]:
    """All messages involving a user (sent + received), oldest-first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, sender, recipient, content, delivered, sent_at, delivered_at
            FROM   messages WHERE sender=? OR recipient=?
            ORDER  BY id DESC LIMIT ?
            """,
            (username, username, limit),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in reversed(rows)]


async def get_all_messages(limit: int = 500) -> list[dict]:
    """Most-recent N messages across all users, returned oldest-first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, sender, recipient, content, delivered, sent_at, delivered_at FROM messages ORDER BY id DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in reversed(rows)]


#  File transfer metadata helpers 

async def save_transfer(
    transfer_id: str, sender: str, receiver: str,
    filename: str, filesize: int, disk_needed: int, status: str = "offered",
) -> bool:
    """
    Insert file transfer record when offer is made.
    disk_needed = bytes receiver must have free (filesize + 10% buffer).
    NO file bytes stored here — metadata only.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO transfers
                    (transfer_id, sender, receiver, filename, filesize, disk_needed, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (transfer_id, sender, receiver, filename, filesize, disk_needed, status),
            )
            await db.commit()
        logger.info(
            f" [DB] transfer {transfer_id[:8]}… '{sender}''{receiver}' "
            f"'{filename}' {filesize}B status={status}"
        )
        return True
    except Exception as e:
        logger.error(f" [DB] save_transfer failed: {e}")
        return False


async def update_transfer_status(transfer_id: str, status: str) -> bool:
    """
    Update transfer status. Terminal states stamp completed_at timestamp.
    Terminal states: completed, failed, aborted, rejected
    """
    terminal = {"completed", "failed", "aborted", "rejected"}
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            if status in terminal:
                await db.execute(
                    "UPDATE transfers SET status=?, completed_at=datetime('now') WHERE transfer_id=?",
                    (status, transfer_id),
                )
            else:
                await db.execute(
                    "UPDATE transfers SET status=? WHERE transfer_id=?",
                    (status, transfer_id),
                )
            await db.commit()
        logger.info(f" [DB] transfer {transfer_id[:8]}…  {status}")
        return True
    except Exception as e:
        logger.error(f" [DB] update_transfer_status failed: {e}")
        return False


async def get_all_transfers(limit: int = 100) -> list[dict]:
    """All transfer records, most-recent first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT transfer_id, sender, receiver, filename, filesize,
                   disk_needed, status, started_at, completed_at
            FROM   transfers ORDER BY started_at DESC LIMIT ?
            """,
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_user_transfers(username: str, limit: int = 50) -> list[dict]:
    """Transfer records for one user (sent + received), most-recent first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT transfer_id, sender, receiver, filename, filesize,
                   disk_needed, status, started_at, completed_at
            FROM   transfers WHERE sender=? OR receiver=?
            ORDER  BY started_at DESC LIMIT ?
            """,
            (username, username, limit),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]