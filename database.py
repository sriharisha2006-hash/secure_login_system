import sqlite3
import os
import logging
from contextlib import contextmanager
from config import Config

logger = logging.getLogger(__name__)

def get_db_path(db_path=None):
    """Resolve database path from argument, Flask app context, or default config."""
    if db_path:
        return db_path
    try:
        from flask import current_app, has_app_context
        if has_app_context() and current_app.config.get('DATABASE_PATH'):
            return current_app.config['DATABASE_PATH']
    except Exception:
        pass
    return Config.DATABASE_PATH

def get_db_connection(db_path=None):
    """
    Establish a connection to the SQLite database.
    Configures row_factory for name-based column access and enables foreign keys.
    """
    path = get_db_path(db_path)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    # Write-Ahead Logging for better concurrent read/write performance
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

@contextmanager
def get_db(db_path=None):
    """
    Context manager providing safe database connection with auto-commit and rollback.
    """
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error during transaction: {e}")
        raise
    finally:
        conn.close()

def init_db(db_path=None):
    """
    Initialize all database tables and indexes safely.
    Uses strict schema definitions with parameterized structure.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        
        # 1. Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                hash_algo TEXT NOT NULL DEFAULT 'bcrypt',
                is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
                totp_secret TEXT DEFAULT NULL,
                backup_codes TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login_at TIMESTAMP DEFAULT NULL,
                last_login_ip TEXT DEFAULT NULL
            );
        """)
        
        # 2. Login attempts table for rate limiting and brute force protection
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                email TEXT DEFAULT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER NOT NULL DEFAULT 0
            );
        """)
        
        # 3. Security audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                details TEXT DEFAULT NULL,
                ip_address TEXT DEFAULT NULL,
                user_agent TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)
        
        # 4. Active session tracking for server-side validation & remote logout
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                session_token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                ip_address TEXT DEFAULT NULL,
                user_agent TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)
        
        # 5. Indexes for fast lookup and query optimization
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, attempted_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email, attempted_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_logs_user ON security_logs(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_active_sessions_user ON active_sessions(user_id);")
        
        logger.info("Database initialized successfully.")

# Safe parameterized query helper functions to eliminate any risk of SQL injection

def execute_query(query, params=(), db_path=None):
    """
    Execute a parameterized SQL statement (INSERT, UPDATE, DELETE).
    Parameters MUST be passed as a tuple or dict to ensure parameterized execution.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.rowcount

def execute_insert(query, params=(), db_path=None):
    """
    Execute a parameterized INSERT statement and return the inserted row id.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.lastrowid

def fetch_one(query, params=(), db_path=None):
    """
    Fetch a single row using a parameterized query.
    Returns sqlite3.Row or None.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None

def fetch_all(query, params=(), db_path=None):
    """
    Fetch all rows matching a parameterized query.
    Returns list of dicts.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
