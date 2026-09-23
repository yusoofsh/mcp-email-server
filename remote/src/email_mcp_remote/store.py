"""Bounded SQLite state with atomic code consumption and refresh rotation.

Opaque credentials are indexed by SHA-256. Their plaintext is never persisted.
This database is for one operator, on a local persistent volume, not NFS.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class StateFull(Exception):
    """Refuse new state rather than grow without a bound."""


class Store:
    def __init__(self, path: Path, binding: str):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or not path.parent.is_dir():
            raise ValueError("Auth state must be a regular local file")
        if path.exists() and (not path.is_file() or path.stat().st_uid != os.getuid()):
            raise ValueError("Auth database has an unsafe owner or file type")
        self.path = path
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=5, check_same_thread=False, isolation_level=None)
        os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        schema = self.db.execute("PRAGMA user_version").fetchone()[0]
        if schema not in (0, 1):
            raise ValueError("Unsupported auth database schema; do not downgrade")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS records (
                kind TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL,
                expires REAL NOT NULL, PRIMARY KEY(kind,key));
            CREATE INDEX IF NOT EXISTS records_expiry ON records(expires);
            CREATE TABLE IF NOT EXISTS families (
                id TEXT PRIMARY KEY, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS rates (
                key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires REAL NOT NULL);
            PRAGMA user_version=1;
        """)
        with self.transaction():
            previous = self.db.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
            if previous and previous[0] != binding:
                # A changed operator/hash/issuer invalidates every existing grant.
                self.db.execute("DELETE FROM records WHERE kind != 'client'")
                self.db.execute("DELETE FROM families")
            self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('binding',?)", (binding,))

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.db.rollback()
                raise
            else:
                self.db.commit()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def _clean(self) -> None:
        now = time.time()
        self.db.execute("DELETE FROM records WHERE expires < ?", (now,))
        self.db.execute("DELETE FROM families WHERE expires < ?", (now,))
        self.db.execute("DELETE FROM rates WHERE expires < ?", (now,))

    def _put(self, kind: str, key: str, data: dict[str, Any], expires: float) -> None:
        self._clean()
        cap = 128 if kind == "client" else 4096
        count = self.db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (kind,)).fetchone()[0]
        existing = self.db.execute("SELECT 1 FROM records WHERE kind=? AND key=?", (kind, key)).fetchone()
        if count >= cap and not existing:
            raise StateFull("OAuth state limit reached")
        self.db.execute(
            "INSERT OR REPLACE INTO records VALUES (?,?,?,?)",
            (kind, key, json.dumps(data, separators=(",", ":")), expires),
        )

    def put(self, kind: str, key: str, data: dict[str, Any], expires: float) -> None:
        with self.transaction():
            self._put(kind, key, data, expires)

    def get(self, kind: str, key: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.db.execute(
                "SELECT data FROM records WHERE kind=? AND key=? AND expires >= ?", (kind, key, time.time())
            ).fetchone()
            return json.loads(row[0]) if row else None

    def pop(self, kind: str, key: str) -> dict[str, Any] | None:
        with self.transaction():
            result = self.get(kind, key)
            self.db.execute("DELETE FROM records WHERE kind=? AND key=?", (kind, key))
            return result

    def allow(self, key: str, limit: int, window: int) -> bool:
        with self.transaction():
            self._clean()
            row = self.db.execute("SELECT count FROM rates WHERE key=?", (key,)).fetchone()
            if row:
                if row[0] >= limit:
                    return False
                self.db.execute("UPDATE rates SET count=count+1 WHERE key=?", (key,))
            else:
                if self.db.execute("SELECT COUNT(*) FROM rates").fetchone()[0] >= 2048:
                    return False
                self.db.execute("INSERT INTO rates VALUES (?,1,?)", (key, time.time() + window))
            return True

    def family_active(self, family: str) -> bool:
        with self.lock:
            return bool(
                self.db.execute(
                    "SELECT 1 FROM families WHERE id=? AND revoked=0 AND expires>=?", (family, time.time())
                ).fetchone()
            )

    def revoke(self, family: str) -> None:
        with self.transaction():
            self.db.execute("UPDATE families SET revoked=1 WHERE id=?", (family,))

    def exchange(
        self,
        kind: str,
        token: str,
        client_id: str,
        new_access: str,
        new_refresh: str,
        access: dict[str, Any],
        refresh: dict[str, Any],
    ) -> bool:
        """Validate and consume a grant and insert its successor in one transaction."""
        with self.transaction():
            old = self.get(kind, digest(token))
            if not old or old["client_id"] != client_id:
                return False
            family = refresh["family"]
            if kind == "refresh":
                if old.get("used"):
                    self.db.execute("UPDATE families SET revoked=1 WHERE id=?", (old["family"],))
                    return False
                if not self.family_active(old["family"]):
                    return False
                old["used"] = True
                self._put("refresh", digest(token), old, old["expires_at"])
            else:
                self.db.execute("DELETE FROM records WHERE kind='code' AND key=?", (digest(token),))
                self.db.execute("INSERT INTO families VALUES (?,?,0)", (family, refresh["expires_at"]))
            self._put("access", digest(new_access), access, access["expires_at"])
            self._put("refresh", digest(new_refresh), refresh, refresh["expires_at"])
            return True
