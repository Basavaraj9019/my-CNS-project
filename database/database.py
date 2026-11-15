"""
SQLite Database Layer for Sender and Receiver applications.
Maintains identity configurations, public key address books (trusted fingerprints),
message history, and replay-protection state.
"""

import sqlite3
import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


class SenderDatabase:
    """Handles sender identity, outbox, and trusted receiver contacts."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sender_profile (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id TEXT UNIQUE NOT NULL,
                    fingerprint TEXT NOT NULL,
                    key_size INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trusted_receivers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    receiver_id TEXT UNIQUE NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    is_verified INTEGER DEFAULT 0,
                    host_ip TEXT,
                    port INTEGER,
                    added_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS outbox (
                    message_id TEXT PRIMARY KEY,
                    receiver_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    plaintext_body TEXT
                )
            """)
            conn.commit()

    def set_profile(self, sender_id: str, fingerprint: str, key_size: int):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sender_profile (sender_id, fingerprint, key_size, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sender_id) DO UPDATE SET
                    fingerprint = excluded.fingerprint,
                    key_size = excluded.key_size
            """, (sender_id, fingerprint, key_size, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def get_profile(self) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sender_profile ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return dict(row) if row else None

    def upsert_receiver(self, receiver_id: str, public_key_pem: str, fingerprint: str, host_ip: str = "", port: int = 5000, is_verified: int = 1):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO trusted_receivers (receiver_id, public_key_pem, fingerprint, is_verified, host_ip, port, added_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(receiver_id) DO UPDATE SET
                    public_key_pem = excluded.public_key_pem,
                    fingerprint = excluded.fingerprint,
                    is_verified = excluded.is_verified,
                    host_ip = excluded.host_ip,
                    port = excluded.port
            """, (receiver_id, public_key_pem, fingerprint, is_verified, host_ip, port, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def get_receiver(self, receiver_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM trusted_receivers WHERE receiver_id = ?", (receiver_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_receivers(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM trusted_receivers ORDER BY added_at DESC")
            return [dict(r) for r in cursor.fetchall()]

    def record_outbox_message(
        self,
        message_id: str,
        receiver_id: str,
        subject: str,
        sha256_hash: str,
        status: str,
        payload_json: str,
        plaintext_body: str
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO outbox (message_id, receiver_id, subject, sha256_hash, sent_at, status, payload_json, plaintext_body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (message_id, receiver_id, subject, sha256_hash, datetime.now(timezone.utc).isoformat(), status, payload_json, plaintext_body))
            conn.commit()

    def list_outbox(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT message_id, receiver_id, subject, sha256_hash, sent_at, status FROM outbox ORDER BY sent_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    def get_outbox_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM outbox WHERE message_id = ?", (message_id,))
            row = cursor.fetchone()
            return dict(row) if row else None


class ReceiverDatabase:
    """Handles receiver identity, inbox, replay protection cache, and trusted senders."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS receiver_profile (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    receiver_id TEXT UNIQUE NOT NULL,
                    fingerprint TEXT NOT NULL,
                    key_size INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trusted_senders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id TEXT UNIQUE NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    is_verified INTEGER DEFAULT 0,
                    added_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS replay_cache (
                    message_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    received_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS inbox (
                    message_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    decrypted_body TEXT,
                    sha256_hash TEXT,
                    raw_envelope_json TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    integrity_status TEXT NOT NULL,
                    signature_status TEXT NOT NULL,
                    non_repudiation_status TEXT NOT NULL,
                    sender_trusted_status TEXT NOT NULL,
                    error_message TEXT
                )
            """)
            conn.commit()

    def set_profile(self, receiver_id: str, fingerprint: str, key_size: int):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO receiver_profile (receiver_id, fingerprint, key_size, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(receiver_id) DO UPDATE SET
                    fingerprint = excluded.fingerprint,
                    key_size = excluded.key_size
            """, (receiver_id, fingerprint, key_size, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def get_profile(self) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM receiver_profile ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return dict(row) if row else None

    def is_message_replayed(self, message_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM replay_cache WHERE message_id = ?", (message_id,))
            return cursor.fetchone() is not None

    def register_replay_cache(self, message_id: str, sender_id: str, timestamp: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO replay_cache (message_id, sender_id, timestamp, received_at)
                VALUES (?, ?, ?, ?)
            """, (message_id, sender_id, timestamp, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def upsert_trusted_sender(self, sender_id: str, public_key_pem: str, fingerprint: str, is_verified: int = 1):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO trusted_senders (sender_id, public_key_pem, fingerprint, is_verified, added_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(sender_id) DO UPDATE SET
                    public_key_pem = excluded.public_key_pem,
                    fingerprint = excluded.fingerprint,
                    is_verified = excluded.is_verified
            """, (sender_id, public_key_pem, fingerprint, is_verified, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def get_trusted_sender(self, sender_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM trusted_senders WHERE sender_id = ?", (sender_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_trusted_senders(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM trusted_senders ORDER BY added_at DESC")
            return [dict(r) for r in cursor.fetchall()]

    def record_inbox_message(
        self,
        message_id: str,
        sender_id: str,
        receiver_id: str,
        subject: str,
        timestamp: str,
        raw_envelope_json: str,
        decrypted_body: Optional[str],
        sha256_hash: Optional[str],
        verification_status: str,
        integrity_status: str,
        signature_status: str,
        non_repudiation_status: str,
        sender_trusted_status: str,
        error_message: Optional[str] = None
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO inbox (
                    message_id, sender_id, receiver_id, subject, timestamp,
                    received_at, decrypted_body, sha256_hash, raw_envelope_json,
                    verification_status, integrity_status, signature_status,
                    non_repudiation_status, sender_trusted_status, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                message_id, sender_id, receiver_id, subject, timestamp,
                datetime.now(timezone.utc).isoformat(), decrypted_body, sha256_hash,
                raw_envelope_json, verification_status, integrity_status,
                signature_status, non_repudiation_status, sender_trusted_status, error_message
            ))
            conn.commit()

    def list_inbox(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT message_id, sender_id, receiver_id, subject, timestamp, received_at,
                       verification_status, integrity_status, signature_status,
                       non_repudiation_status, sender_trusted_status, error_message
                FROM inbox ORDER BY received_at DESC LIMIT ?
            """, (limit,))
            return [dict(r) for r in cursor.fetchall()]

    def get_inbox_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM inbox WHERE message_id = ?", (message_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
