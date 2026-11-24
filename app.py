import os
import json
from flask import (
    Flask, render_template, request, redirect, url_for, flash, 
    session, g, abort, make_response
)
from config import Config
from database import init_db, fetch_one, fetch_all, execute_insert, execute_query
import auth
import security

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database on startup
with app.app_context():
    init_db()

# -------------------------------------------------------------
# Template Context Processors & Security Headers
# -------------------------------------------------------------

@app.context_processor
def inject_security_context():
    """
    Expose CSRF token, current logged in user (if any), and app configuration to all templates.
    """
    user = None
    if security.is_user_authenticated():
        user = fetch_one(
            "SELECT id, name, email, is_2fa_enabled, created_at, last_login_at, last_login_ip FROM users WHERE id = ?",
            (session['user_id'],)
        )
    return {
        'csrf_token': security.generate_csrf_token(),
        'current_user': user,
        'app_name': Config.APP_NAME,
        'password_min_length': Config.PASSWORD_MIN_LENGTH
    }

@app.before_request
def csrf_protect_and_track():
    """
    Enforce CSRF token verification on all mutating requests (POST, PUT, DELETE, PATCH).
    Allows bypassing CSRF strictly when running under test harness (app.config['TESTING']).
    """
    if app.config.get('TESTING'):
        return
        
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        if not token or not security.validate_csrf_token(token):
            app.logger.warning(f"CSRF validation failed for IP {request.remote_addr} on {request.path}")
            abort(403, description="CSRF validation failed. Form submission token was missing or expired.")

@app.after_request
def add_security_headers(response):
    """
    Add industry-standard HTTP security headers to all responses.
    """
    # Content Security Policy (allows local fonts and inline styles for UI enhancements, allows data: URIs for QR code)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Disable caching for sensitive authenticated routes
    if security.is_user_authenticated() or request.path.startswith('/login') or request.path.startswith('/security'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        
    return response

# -------------------------------------------------------------
# Core Routes
# -------------------------------------------------------------

@app.route('/')
def index():
    """Root endpoint: Redirect to dashboard if authenticated, else to login."""
    if security.is_user_authenticated():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration route:
    - Input validation on backend (name, email, password strength, confirmation)
    - Duplicate email check (parameterized)
    - Cryptographic password hashing (bcrypt or argon2)
    - Audit logging
    """
    if security.is_user_authenticated():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        algo = request.form.get('hash_algo', Config.DEFAULT_HASH_ALGO).lower()
        if algo not in ('bcrypt', 'argon2'):
            algo = Config.DEFAULT_HASH_ALGO

        errors = []

        # 1. Validate full name
        is_name_valid, clean_name, name_err = auth.validate_name(name)
        if not is_name_valid:
            errors.append(name_err)

        # 2. Validate email format
        is_email_valid, clean_email, email_err = auth.validate_email(email)
        if not is_email_valid:
            errors.append(email_err)

        # 3. Validate password match
        if password != confirm_password:
            errors.append("Passwords do not match.")

        # 4. Validate password complexity
        is_pwd_valid, pwd_errors, _ = auth.validate_password_strength(password)
        if not is_pwd_valid:
            errors.extend(pwd_errors)

        # 5. Check if email already registered (parameterized query)
        if is_email_valid:
            existing_user = fetch_one("SELECT id FROM users WHERE email = ?", (clean_email,))
            if existing_user:
                errors.append("An account with this email address is already registered.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template('register.html', name=name, email=email, selected_algo=algo), 400

        # Secure password hashing (never store plain-text)
        password_hash = auth.hash_password(password, algo=algo)

        # Parameterized INSERT prevents SQL injection
        user_id = execute_insert(
            """
            INSERT INTO users (name, email, password_hash, hash_algo, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            """,
            (clean_name, clean_email, password_hash, algo)
        )

        # Security audit log
        security.log_security_event(
            user_id, 
            "USER_REGISTRATION", 
            f"User account created using {algo} hashing.",
            request.remote_addr, 
            request.headers.get('User-Agent')
        )

        flash("Registration successful! You can now log in securely.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', selected_algo=Config.DEFAULT_HASH_ALGO)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login route:
    - Rate limit enforcement
    - Parameterized user lookup
    - Password verification (bcrypt/argon2)
    - 2FA routing if enabled
    - Secure session establishment and audit logging
    """
    if security.is_user_authenticated():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr

        # 1. Rate Limiting Check
        is_allowed, remaining, retry_after = security.check_rate_limit(client_ip, email)
        if not is_allowed:
            security.log_security_event(
                None, "RATE_LIMIT_BLOCKED",
                f"Login blocked due to rate limit for {email}. Retry after {retry_after}s",
                client_ip, request.headers.get('User-Agent')
            )
            flash(
                f"Too many failed login attempts. For security, please try again in {retry_after} seconds.",
                "danger"
            )
            return render_template('login.html', email=email, is_locked=True, retry_after=retry_after), 429

        # Basic input check
        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return render_template('login.html', email=email), 400

        # Parameterized query lookup
        user = fetch_one("SELECT * FROM users WHERE email = ?", (email.lower(),))

        # Password verification
        is_valid_pwd = False
        if user:
            is_valid_pwd = auth.verify_password(password, user['password_hash'], user.get('hash_algo'))

        if not user or not is_valid_pwd:
            # Record failed login attempt
            security.record_login_attempt(client_ip, email, success=False)
            security.log_security_event(
                user['id'] if user else None,
                "LOGIN_FAILED",
                f"Failed login attempt for email {email}",
                client_ip, request.headers.get('User-Agent')
            )
            
            # Recheck remaining attempts to inform user
            _, remaining_after, _ = security.check_rate_limit(client_ip, email)
            warning_msg = "Invalid email or password."
            if remaining_after <= 2 and remaining_after > 0:
                warning_msg += f" Warning: {remaining_after} attempt(s) remaining before temporary lockout."
                
            flash(warning_msg, "danger")
            return render_template('login.html', email=email), 401

        # Clear failed login attempts upon successful password match
        security.clear_failed_attempts(client_ip, email)

        # Check if Two-Factor Authentication is enabled
        if user['is_2fa_enabled']:
            # Store temporary authentication challenge in session (not full login yet)
            session['pending_2fa_user_id'] = user['id']
            session['pending_2fa_email'] = user['email']
            flash("Password verified. Please enter your 2FA authentication code.", "info")
            return redirect(url_for('login_2fa'))

        # Standard authentication: create full session
        security.create_user_session(user['id'], client_ip, request.headers.get('User-Agent'))
        security.log_security_event(
            user['id'], "LOGIN_SUCCESS", "User authenticated successfully.",
            client_ip, request.headers.get('User-Agent')
        )

        flash(f"Welcome back, {user['name']}!", "success")
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/') and not next_page.startswith('//'):
            return redirect(next_page)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    """
    Two-Factor Authentication challenge during login.
    Requires password verification first (pending_2fa_user_id in session).
    """
    pending_user_id = session.get('pending_2fa_user_id')
    if not pending_user_id:
        return redirect(url_for('login'))

    user = fetch_one("SELECT * FROM users WHERE id = ?", (pending_user_id,))
    if not user or not user['is_2fa_enabled']:
        session.pop('pending_2fa_user_id', None)
        return redirect(url_for('login'))

    client_ip = request.remote_addr

    if request.method == 'POST':
        token = request.form.get('totp_code', '').strip()
        backup_code = request.form.get('backup_code', '').strip()
        auth_success = False

        if backup_code:
            # Verify backup recovery code
            is_valid_backup, updated_codes_json = auth.verify_and_consume_backup_code(backup_code, user['backup_codes'])
            if is_valid_backup:
                auth_success = True
                # Update remaining backup codes
                execute_query("UPDATE users SET backup_codes = ? WHERE id = ?", (updated_codes_json, user['id']))
                security.log_security_event(
                    user['id'], "2FA_BACKUP_CODE_USED", "Authenticated using a backup recovery code.",
                    client_ip, request.headers.get('User-Agent')
                )
        elif token:
            # Verify 6-digit TOTP token
            if auth.verify_totp_token(user['totp_secret'], token):
                auth_success = True

        if not auth_success:
            flash("Invalid two-factor authentication code. Please try again.", "danger")
            security.log_security_event(
                user['id'], "2FA_CHALLENGE_FAILED", "Failed 2FA code verification attempt.",
                client_ip, request.headers.get('User-Agent')
            )
            return render_template('two_factor.html', email=user['email']), 401

        # Clear pending 2FA state
        session.pop('pending_2fa_user_id', None)
        session.pop('pending_2fa_email', None)

        # Establish authenticated session
        security.create_user_session(user['id'], client_ip, request.headers.get('User-Agent'))
        security.log_security_event(
            user['id'], "LOGIN_SUCCESS_2FA", "User successfully authenticated via 2FA.",
            client_ip, request.headers.get('User-Agent')
        )

        flash(f"Welcome back, {user['name']}! Two-Factor Authentication confirmed.", "success")
        return redirect(url_for('dashboard'))

    return render_template('two_factor.html', email=user['email'])

@app.route('/dashboard')
@security.login_required
def dashboard():
    """
    Authenticated user dashboard:
    - User details (name, email, registration date, last login)
    - Security posture overview (2FA status, hashing algorithm used)
    - Active session details
    - Recent security audit logs
    """
    user_id = session['user_id']
    user = fetch_one(
        "SELECT id, name, email, hash_algo, is_2fa_enabled, created_at, last_login_at, last_login_ip FROM users WHERE id = ?",
        (user_id,)
    )
    if not user:
        security.destroy_user_session()
        return redirect(url_for('login'))

    # Retrieve recent security logs for current user
    logs = fetch_all(
        """
        SELECT event_type, details, ip_address, created_at
        FROM security_logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 8
        """,
        (user_id,)
    )

    # Active sessions count
    sessions_count = fetch_one("SELECT COUNT(*) as cnt FROM active_sessions WHERE user_id = ?", (user_id,))
    active_count = sessions_count['cnt'] if sessions_count else 1

    return render_template(
        'dashboard.html',
        user=user,
        logs=logs,
        active_sessions_count=active_count,
        client_ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown')
    )

@app.route('/security/2fa/setup', methods=['GET', 'POST'])
@security.login_required
def setup_2fa():
    """
    2FA configuration workflow:
    - Generates base32 secret and QR code data URL
    - Generates backup recovery codes
    - Verifies user's first 6-digit code before activating
    """
    user_id = session['user_id']
    user = fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))

    if user['is_2fa_enabled']:
        flash("Two-Factor Authentication is already enabled for your account.", "info")
        return redirect(url_for('dashboard'))

    if request.method == 'GET':
        # Generate new secret and backup codes, store temporarily in session
        secret = auth.generate_totp_secret()
        session['temp_totp_secret'] = secret
        plain_backup_codes, hashed_backup_codes = auth.generate_backup_codes()
        session['temp_backup_codes_plain'] = plain_backup_codes
        session['temp_backup_codes_hashed'] = hashed_backup_codes

        totp_uri = auth.get_totp_uri(secret, user['email'], issuer="SecureAuth Portal")
        qr_code_b64 = auth.generate_qr_code_base64(totp_uri)

        return render_template(
            'two_factor_setup.html',
            secret=secret,
            qr_code=qr_code_b64,
            backup_codes=plain_backup_codes
        )

    if request.method == 'POST':
        code = request.form.get('totp_code', '').strip()
        secret = session.get('temp_totp_secret')
        hashed_codes = session.get('temp_backup_codes_hashed')

        if not secret or not hashed_codes:
            flash("Session expired. Please start the 2FA setup process again.", "warning")
            return redirect(url_for('setup_2fa'))

        # Verify the user entered the correct token from their app
        if not auth.verify_totp_token(secret, code):
            flash("Invalid verification code. Please check your authenticator app and try again.", "danger")
            # Re-render setup page with existing temporary secret
            totp_uri = auth.get_totp_uri(secret, user['email'], issuer="SecureAuth Portal")
            qr_code_b64 = auth.generate_qr_code_base64(totp_uri)
            return render_template(
                'two_factor_setup.html',
                secret=secret,
                qr_code=qr_code_b64,
                backup_codes=session.get('temp_backup_codes_plain', [])
            ), 400

        # Enable 2FA on the user account
        execute_query(
            """
            UPDATE users 
            SET is_2fa_enabled = 1, totp_secret = ?, backup_codes = ?
            WHERE id = ?
            """,
            (secret, json.dumps(hashed_codes), user_id)
        )

        # Clear temp session variables
        session.pop('temp_totp_secret', None)
        session.pop('temp_backup_codes_plain', None)
        session.pop('temp_backup_codes_hashed', None)

        security.log_security_event(
            user_id, "2FA_ENABLED", "Two-Factor Authentication was successfully activated.",
            request.remote_addr, request.headers.get('User-Agent')
        )

        flash("Two-Factor Authentication has been successfully enabled for your account!", "success")
        return redirect(url_for('dashboard'))

@app.route('/security/2fa/disable', methods=['POST'])
@security.login_required
def disable_2fa():
    """
    Disable 2FA:
    Requires user password verification to prevent unauthorized changes.
    """
    user_id = session['user_id']
    password = request.form.get('password', '')

    user = fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not user or not auth.verify_password(password, user['password_hash'], user.get('hash_algo')):
        flash("Incorrect password. Cannot disable Two-Factor Authentication.", "danger")
        return redirect(url_for('dashboard'))

    execute_query(
        """
        UPDATE users 
        SET is_2fa_enabled = 0, totp_secret = NULL, backup_codes = NULL
        WHERE id = ?
        """,
        (user_id,)
    )

    security.log_security_event(
        user_id, "2FA_DISABLED", "Two-Factor Authentication was disabled.",
        request.remote_addr, request.headers.get('User-Agent')
    )

    flash("Two-Factor Authentication has been disabled.", "warning")
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    Secure logout route:
    - Destroys active session in database
    - Clears all session cookies
    - Adds security audit record
    """
    security.destroy_user_session()
    flash("You have been logged out securely.", "info")
    return redirect(url_for('login'))

# -------------------------------------------------------------
# Error Handlers
# -------------------------------------------------------------

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', code=400, title="Bad Request", message=str(e)), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, title="Forbidden", message="Access denied or CSRF token verification failed."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, title="Page Not Found", message="The requested resource could not be found."), 404

@app.errorhandler(429)
def too_many_requests(e):
    return render_template('error.html', code=429, title="Too Many Requests", message="Rate limit exceeded. Please wait a few moments before trying again."), 429

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, title="Internal Server Error", message="A secure server error occurred. Please try again shortly."), 500

if __name__ == '__main__':
    # Start local server on 127.0.0.1:5000
    print("=" * 60)
    print(f" {Config.APP_NAME} running at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=False)
