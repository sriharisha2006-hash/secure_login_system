import hmac
import secrets
import time
from datetime import datetime
from functools import wraps
from flask import request, session, abort, redirect, url_for, flash
from config import Config
from database import execute_query, execute_insert, fetch_one, fetch_all

# -------------------------------------------------------------
# Rate Limiting
# -------------------------------------------------------------

def record_login_attempt(ip_address: str, email: str, success: bool):
    """
    Record an authentication attempt into the database with timestamp and outcome.
    Parameterized query ensures SQL injection protection.
    """
    execute_insert(
        """
        INSERT INTO login_attempts (ip_address, email, attempted_at, success)
        VALUES (?, ?, datetime('now'), ?)
        """,
        (ip_address, email.strip().lower() if email else None, 1 if success else 0)
    )

def check_rate_limit(ip_address: str, email: str = None) -> tuple[bool, int, int]:
    """
    Check if login rate limit has been exceeded for either the given IP address or email.
    Window: Config.RATE_LIMIT_LOGIN_WINDOW_SECONDS
    Max attempts: Config.RATE_LIMIT_LOGIN_MAX_ATTEMPTS
    
    Returns:
      (is_allowed, remaining_attempts, retry_after_seconds)
    """
    window_seconds = Config.RATE_LIMIT_LOGIN_WINDOW_SECONDS
    max_attempts = Config.RATE_LIMIT_LOGIN_MAX_ATTEMPTS
    
    # Query failed attempts for this IP in the current window
    ip_stats = fetch_one(
        f"""
        SELECT COUNT(*) as failures,
               MAX(strftime('%s', attempted_at)) as last_attempt_epoch
        FROM login_attempts
        WHERE ip_address = ? AND success = 0
          AND attempted_at >= datetime('now', '-{window_seconds} seconds')
        """,
        (ip_address,)
    )
    
    ip_failures = ip_stats['failures'] if ip_stats else 0
    
    # Also check failures for this specific email address if provided
    email_failures = 0
    email_last_epoch = 0
    if email:
        email_stats = fetch_one(
            f"""
            SELECT COUNT(*) as failures,
                   MAX(strftime('%s', attempted_at)) as last_attempt_epoch
            FROM login_attempts
            WHERE email = ? AND success = 0
              AND attempted_at >= datetime('now', '-{window_seconds} seconds')
            """,
            (email.strip().lower(),)
        )
        if email_stats:
            email_failures = email_stats['failures'] or 0
            email_last_epoch = email_stats['last_attempt_epoch'] or 0

    total_relevant_failures = max(ip_failures, email_failures)
    
    if total_relevant_failures >= max_attempts:
        # Determine remaining lockout seconds
        now_epoch = int(time.time())
        ip_last = int(ip_stats['last_attempt_epoch']) if (ip_stats and ip_stats['last_attempt_epoch']) else now_epoch
        email_last = int(email_last_epoch) if email_last_epoch else now_epoch
        last_epoch = max(ip_last, email_last)
        elapsed = max(0, now_epoch - last_epoch)
        retry_after = max(1, window_seconds - elapsed)
        return False, 0, retry_after
        
    remaining = max_attempts - total_relevant_failures
    return True, remaining, 0

def clear_failed_attempts(ip_address: str, email: str = None):
    """
    Reset failed login attempts upon successful authentication.
    """
    if email:
        execute_query(
            "DELETE FROM login_attempts WHERE (ip_address = ? OR email = ?) AND success = 0",
            (ip_address, email.strip().lower())
        )
    else:
        execute_query(
            "DELETE FROM login_attempts WHERE ip_address = ? AND success = 0",
            (ip_address,)
        )

# -------------------------------------------------------------
# CSRF Protection
# -------------------------------------------------------------

def generate_csrf_token() -> str:
    """
    Generate or retrieve a cryptographically secure CSRF token stored in session.
    """
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token(token: str) -> bool:
    """
    Validate CSRF token using constant-time comparison to prevent timing side channels.
    """
    stored_token = session.get('_csrf_token')
    if not stored_token or not token:
        return False
    return hmac.compare_digest(str(stored_token), str(token))

# -------------------------------------------------------------
# Session Management & Invalidation
# -------------------------------------------------------------

def create_user_session(user_id: int, ip_address: str, user_agent: str) -> str:
    """
    Establish a safe user session:
    1. Clear any prior session data (session fixation defense)
    2. Generate high-entropy session token
    3. Store active session in database
    4. Store session variables in encrypted/signed cookie
    """
    session.clear()
    
    session_token = secrets.token_hex(32)
    session['user_id'] = user_id
    session['session_token'] = session_token
    session['created_at'] = int(time.time())
    session.permanent = True
    
    # Store in database
    execute_insert(
        """
        INSERT OR REPLACE INTO active_sessions (session_token, user_id, ip_address, user_agent, created_at, last_activity)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
        """,
        (session_token, user_id, ip_address, user_agent[:255] if user_agent else None)
    )
    
    # Update last login info on user record
    execute_query(
        """
        UPDATE users 
        SET last_login_at = datetime('now'), last_login_ip = ?
        WHERE id = ?
        """,
        (ip_address, user_id)
    )
    
    return session_token

def is_user_authenticated() -> bool:
    """
    Verify whether the current request is backed by an authenticated, valid server session.
    """
    user_id = session.get('user_id')
    session_token = session.get('session_token')
    
    if not user_id or not session_token:
        return False
        
    # Check server-side active_sessions table
    record = fetch_one(
        "SELECT session_token FROM active_sessions WHERE session_token = ? AND user_id = ?",
        (session_token, user_id)
    )
    
    if not record:
        session.clear()
        return False
        
    # Refresh activity timestamp periodically
    try:
        execute_query(
            "UPDATE active_sessions SET last_activity = datetime('now') WHERE session_token = ?",
            (session_token,)
        )
    except Exception:
        pass
        
    return True

def destroy_user_session():
    """
    Fully terminate user session on both server and client.
    """
    session_token = session.get('session_token')
    user_id = session.get('user_id')
    
    if session_token:
        execute_query("DELETE FROM active_sessions WHERE session_token = ?", (session_token,))
        
    if user_id:
        log_security_event(user_id, "LOGOUT", "User logged out successfully.", request.remote_addr, request.headers.get('User-Agent'))
        
    session.clear()

# -------------------------------------------------------------
# Security Audit Logging
# -------------------------------------------------------------

def log_security_event(user_id: int | None, event_type: str, details: str, ip_address: str, user_agent: str):
    """
    Append an entry to the audit log.
    """
    execute_insert(
        """
        INSERT INTO security_logs (user_id, event_type, details, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        """,
        (user_id, event_type, details, ip_address, (user_agent or '')[:255])
    )

# -------------------------------------------------------------
# Route Protection Decorators
# -------------------------------------------------------------

def login_required(f):
    """
    Decorator to restrict route access strictly to authenticated users.
    Redirects unauthenticated users to login with informative flash message.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_user_authenticated():
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login', next=request.endpoint))
        return f(*args, **kwargs)
    return decorated_function
