import sqlite3
import os

DATABASE_PATH = os.environ.get("DATABASE_PATH", "connector.db")


def get_db():
    """Open a connection to the SQLite database.

    Returns:
        sqlite3.Connection: Connection with Row factory and WAL mode enabled.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create the customers table if it doesn't exist.

    Called once at startup.
    """
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            wazuh_groups TEXT NOT NULL DEFAULT '[]',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()
