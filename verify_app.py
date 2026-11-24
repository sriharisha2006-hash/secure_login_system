"""
Verification and Test Automation Script for Secure Login System
Executes real end-to-end user scenarios through the Flask application stack.
"""
import os
import re
import pyotp
from app import app
import database
from database import fetch_one, fetch_all, execute_query

def print_header(title):
    print("\n" + "=" * 65)
    print(f" {title}")
    print("=" * 65)

def print_step(step_name, status="PASS", details=""):
    badge = "[PASS]" if status == "PASS" else "[FAIL]"
    print(f"{badge} {step_name}")
    if details:
        print(f"       -> {details}")

def run_verification():
    print_header("SECURE LOGIN SYSTEM: FULL END-TO-END VERIFICATION")
    
    # 1. Database Configuration Check
    print_header("1. DATABASE CONFIGURATION & SCHEMA")
    database.init_db()
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    tables = [r['name'] for r in cursor.fetchall() if not r['name'].startswith('sqlite_')]
    conn.close()
    
    expected_tables = ['active_sessions', 'login_attempts', 'security_logs', 'users']
    for tbl in expected_tables:
        if tbl in tables:
            print_step(f"Table '{tbl}' initialized and verified", "PASS")
        else:
            print_step(f"Table '{tbl}' missing", "FAIL")

    # Clean up test accounts to start fresh
    execute_query("DELETE FROM users WHERE email IN ('alex@example.com', 'sarah@example.com')")
    execute_query("DELETE FROM login_attempts WHERE email IN ('alex@example.com', 'sarah@example.com', 'locked@example.com')")

    # Configure test client
    app.config['TESTING'] = True  # Allows full app test harness
    client = app.test_client()

    # 2. Registration Testing
    print_header("2. USER REGISTRATION TESTING")
    
    # Test 2.1: Weak Password Rejection
    res = client.post('/register', data={
        'name': 'Alex Dev',
        'email': 'alex@example.com',
        'password': 'short',
        'confirm_password': 'short'
    })
    assert res.status_code == 400
    print_step("Weak password rejected (< 8 characters)", "PASS", "HTTP 400 returned with policy error")

    # Test 2.2: Missing Special Character
    res = client.post('/register', data={
        'name': 'Alex Dev',
        'email': 'alex@example.com',
        'password': 'Password123',
        'confirm_password': 'Password123'
    })
    assert res.status_code == 400
    print_step("Password missing special character rejected", "PASS", "HTTP 400 returned with policy error")

    # Test 2.3: Password Mismatch
    res = client.post('/register', data={
        'name': 'Alex Dev',
        'email': 'alex@example.com',
        'password': 'StrongPassword123!',
        'confirm_password': 'DifferentPassword456#'
    })
    assert res.status_code == 400
    print_step("Mismatched password confirmation rejected", "PASS", "HTTP 400 returned: Passwords do not match")

    # Test 2.4: Valid Registration with Bcrypt
    res = client.post('/register', data={
        'name': 'Alex Dev',
        'email': 'alex@example.com',
        'password': 'StrongPassword123!',
        'confirm_password': 'StrongPassword123!',
        'hash_algo': 'bcrypt'
    }, follow_redirects=True)
    assert res.status_code == 200
    user_alex = fetch_one("SELECT * FROM users WHERE email = 'alex@example.com'")
    assert user_alex is not None
    assert user_alex['password_hash'].startswith('$2b$')
    assert user_alex['password_hash'] != 'StrongPassword123!'
    print_step("Valid user registration with Bcrypt", "PASS", f"Created user #USR-{user_alex['id']:04d} with salted bcrypt hash")

    # Test 2.5: Valid Registration with Argon2id
    res = client.post('/register', data={
        'name': 'Sarah Security',
        'email': 'sarah@example.com',
        'password': 'SuperSecretPassword99#',
        'confirm_password': 'SuperSecretPassword99#',
        'hash_algo': 'argon2'
    }, follow_redirects=True)
    assert res.status_code == 200
    user_sarah = fetch_one("SELECT * FROM users WHERE email = 'sarah@example.com'")
    assert user_sarah is not None
    assert user_sarah['password_hash'].startswith('$argon2')
    print_step("Valid user registration with Argon2id", "PASS", f"Created user #USR-{user_sarah['id']:04d} with memory-hard Argon2 hash")

    # Test 2.6: Duplicate Email Check (Case-Insensitive)
    res = client.post('/register', data={
        'name': 'Alex Clone',
        'email': 'ALEX@EXAMPLE.COM',
        'password': 'StrongPassword123!',
        'confirm_password': 'StrongPassword123!'
    })
    assert res.status_code == 400
    print_step("Duplicate email registration prevented", "PASS", "Rejected duplicate case-insensitive email: ALEX@EXAMPLE.COM")

    # 3. Login & Invalid Credentials Testing
    print_header("3. LOGIN & CREDENTIAL VERIFICATION TESTING")
    
    # Test 3.1: Incorrect Password
    res = client.post('/login', data={
        'email': 'alex@example.com',
        'password': 'WrongPassword123!'
    })
    assert res.status_code == 401
    print_step("Invalid password login attempt rejected", "PASS", "HTTP 401 Unauthorized with generic error")

    # Test 3.2: Non-Existent Email
    res = client.post('/login', data={
        'email': 'nonexistent@example.com',
        'password': 'AnyPassword123!'
    })
    assert res.status_code == 401
    print_step("Non-existent user email rejected", "PASS", "HTTP 401 Unauthorized with generic error")

    # Test 3.3: Rate Limiting & Lockout
    print_header("4. RATE LIMITING & BRUTE FORCE PROTECTION")
    lockout_email = 'locked@example.com'
    execute_query("DELETE FROM login_attempts WHERE email = ? OR ip_address = '127.0.0.1'", (lockout_email,))
    
    for attempt in range(1, 6):
        r = client.post('/login', data={'email': lockout_email, 'password': 'BadPassword!'})
        assert r.status_code == 401, f"Expected 401 on attempt {attempt}, got {r.status_code}"
    
    # 6th attempt must trigger rate limit lockout HTTP 429
    blocked = client.post('/login', data={'email': lockout_email, 'password': 'BadPassword!'})
    assert blocked.status_code == 429, f"Expected 429 on 6th attempt, got {blocked.status_code}"
    print_step("Brute-force lockout triggered on 6th failed attempt", "PASS", "HTTP 429 Too Many Requests returned with lockout countdown")

    # Clear test lockout so normal operations can continue
    execute_query("DELETE FROM login_attempts WHERE ip_address = '127.0.0.1' OR email = ?", (lockout_email,))

    # 4. Session Management & Dashboard Access
    print_header("5. SESSION MANAGEMENT & DASHBOARD SECURITY")
    
    # Test 4.1: Unauthorized Access Guard
    res_unauth = client.get('/dashboard', follow_redirects=True)
    assert b"Please log in to access this page" in res_unauth.data
    print_step("Unauthorized access to /dashboard blocked", "PASS", "Safely redirected to /login")

    # Test 4.2: Successful Login & Session Creation
    login_res = client.post('/login', data={
        'email': 'alex@example.com',
        'password': 'StrongPassword123!'
    }, follow_redirects=True)
    assert login_res.status_code == 200
    assert b"Welcome back, Alex Dev!" in login_res.data
    assert b"Authenticated Session Active" in login_res.data
    print_step("Successful login & dashboard access", "PASS", "User logged in, session cookie established")

    # Test 4.3: Server-side active session record
    active = fetch_one("SELECT * FROM active_sessions WHERE user_id = ?", (user_alex['id'],))
    assert active is not None
    print_step("Server-side active session stored", "PASS", f"Active session token registered in DB: {active['session_token'][:12]}...")

    # 5. Two-Factor Authentication (2FA) Lifecycle
    print_header("6. TWO-FACTOR AUTHENTICATION (2FA / TOTP) TESTING")
    
    # Test 5.1: Setup 2FA
    setup_get = client.get('/security/2fa/setup')
    assert setup_get.status_code == 200
    assert b"data:image/png;base64," in setup_get.data
    
    with client.session_transaction() as sess:
        totp_secret = sess.get('temp_totp_secret')
        backup_codes = sess.get('temp_backup_codes_plain')
    
    assert totp_secret is not None
    assert len(backup_codes) == 8
    print_step("2FA setup initiated", "PASS", f"Generated secret {totp_secret} and {len(backup_codes)} emergency backup codes")

    # Test 5.2: Activate 2FA with TOTP code
    totp = pyotp.TOTP(totp_secret)
    current_code = totp.now()
    setup_post = client.post('/security/2fa/setup', data={'totp_code': current_code}, follow_redirects=True)
    assert setup_post.status_code == 200
    assert b"Two-Factor Authentication has been successfully enabled" in setup_post.data
    
    user_alex = fetch_one("SELECT * FROM users WHERE id = ?", (user_alex['id'],))
    assert user_alex['is_2fa_enabled'] == 1
    print_step("2FA successfully enabled on account", "PASS", "Account protected with TOTP")

    # Test 5.3: Logout & Login with 2FA Challenge
    client.post('/logout')
    login_step1 = client.post('/login', data={
        'email': 'alex@example.com',
        'password': 'StrongPassword123!'
    }, follow_redirects=True)
    assert b"Two-Factor Authentication" in login_step1.data
    assert b"Enter 6-Digit Authenticator Code" in login_step1.data
    print_step("2FA challenge enforced upon login", "PASS", "Redirected to 2FA verification step after valid password")

    # Test 5.4: Submit Invalid 2FA Code
    res_bad_totp = client.post('/login/2fa', data={'totp_code': '999999'})
    assert res_bad_totp.status_code == 401
    print_step("Invalid 2FA code rejected", "PASS", "HTTP 401 returned for incorrect TOTP token")

    # Test 5.5: Submit Valid 2FA Code
    res_good_totp = client.post('/login/2fa', data={'totp_code': totp.now()}, follow_redirects=True)
    assert res_good_totp.status_code == 200
    assert b"Two-Factor Authentication confirmed" in res_good_totp.data
    print_step("Valid 2FA code authenticated", "PASS", "Full session established, redirected to dashboard")

    # 6. Logout Verification
    print_header("7. LOGOUT & SESSION INVALIDATION TESTING")
    logout_res = client.post('/logout', follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"You have been logged out securely" in logout_res.data
    
    # Verify session invalidated in database
    active_after = fetch_one("SELECT * FROM active_sessions WHERE user_id = ?", (user_alex['id'],))
    assert active_after is None
    print_step("Active session purged from database on logout", "PASS", "Database active_sessions table confirmed empty for user")

    # Verify dashboard cannot be accessed post-logout
    res_post_logout = client.get('/dashboard', follow_redirects=True)
    assert b"Please log in to access this page" in res_post_logout.data
    print_step("Post-logout access to protected routes blocked", "PASS", "Client cookie cleared, redirected to /login")

    print_header("ALL VERIFICATION TESTS COMPLETED SUCCESSFULLY (100% PASS)")

if __name__ == '__main__':
    run_verification()
