import os
import unittest
import tempfile
import json
import pyotp
from app import app
from database import init_db, fetch_one, execute_query, get_db
import auth
import security

class SecureLoginSystemTests(unittest.TestCase):
    def setUp(self):
        # Create a fresh temporary database for isolated test execution
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        app.config['DATABASE_PATH'] = self.db_path
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        # Initialize schema in test database
        with app.app_context():
            init_db(self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        try:
            os.remove(self.db_path)
        except Exception:
            pass

    # -------------------------------------------------------------
    # 1. User Registration Tests
    # -------------------------------------------------------------
    def test_01_successful_registration_bcrypt(self):
        """Verify successful user registration with bcrypt password hashing."""
        response = self.client.post('/register', data={
            'name': 'Alice Security',
            'email': 'alice@example.com',
            'password': 'StrongPassword123!',
            'confirm_password': 'StrongPassword123!',
            'hash_algo': 'bcrypt'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration successful", response.data)

        # Check user in database
        user = fetch_one("SELECT * FROM users WHERE email = ?", ('alice@example.com',), self.db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user['name'], 'Alice Security')
        self.assertEqual(user['hash_algo'], 'bcrypt')
        # Plain text password MUST NEVER be stored
        self.assertNotEqual(user['password_hash'], 'StrongPassword123!')
        self.assertTrue(user['password_hash'].startswith('$2b$'))
        self.assertTrue(auth.verify_password('StrongPassword123!', user['password_hash']))

    def test_02_successful_registration_argon2(self):
        """Verify successful user registration with Argon2id password hashing."""
        response = self.client.post('/register', data={
            'name': 'Bob Security',
            'email': 'bob@example.com',
            'password': 'SuperSecretPassword99#',
            'confirm_password': 'SuperSecretPassword99#',
            'hash_algo': 'argon2'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        user = fetch_one("SELECT * FROM users WHERE email = ?", ('bob@example.com',), self.db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user['hash_algo'], 'argon2')
        self.assertTrue(user['password_hash'].startswith('$argon2'))
        self.assertTrue(auth.verify_password('SuperSecretPassword99#', user['password_hash']))

    def test_03_registration_weak_password_rejected(self):
        """Verify that weak passwords failing complexity policy are rejected."""
        # Too short
        res1 = self.client.post('/register', data={
            'name': 'Test User', 'email': 'test1@example.com',
            'password': 'Short1!', 'confirm_password': 'Short1!'
        })
        self.assertEqual(res1.status_code, 400)
        self.assertIn(b"Password must be at least 8 characters long", res1.data)

        # Missing special character
        res2 = self.client.post('/register', data={
            'name': 'Test User', 'email': 'test2@example.com',
            'password': 'NoSpecialChar123', 'confirm_password': 'NoSpecialChar123'
        })
        self.assertEqual(res2.status_code, 400)
        self.assertIn(b"special character", res2.data)

        # Missing numeric digit
        res3 = self.client.post('/register', data={
            'name': 'Test User', 'email': 'test3@example.com',
            'password': 'NoNumericDigit!@#', 'confirm_password': 'NoNumericDigit!@#'
        })
        self.assertEqual(res3.status_code, 400)
        self.assertIn(b"numeric digit", res3.data)

    def test_04_registration_password_mismatch(self):
        """Verify password and confirm_password must match."""
        response = self.client.post('/register', data={
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'StrongPassword123!',
            'confirm_password': 'DifferentPassword123!'
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Passwords do not match", response.data)

    def test_05_registration_duplicate_email(self):
        """Verify duplicate email registrations are prevented."""
        # First registration
        self.client.post('/register', data={
            'name': 'First User', 'email': 'duplicate@example.com',
            'password': 'ValidPassword123!', 'confirm_password': 'ValidPassword123!'
        })
        # Second registration with same email (case-insensitive)
        response = self.client.post('/register', data={
            'name': 'Second User', 'email': 'DUPLICATE@EXAMPLE.COM',
            'password': 'ValidPassword123!', 'confirm_password': 'ValidPassword123!'
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"already registered", response.data)

    # -------------------------------------------------------------
    # 2. User Login & Verification Tests
    # -------------------------------------------------------------
    def test_06_successful_login(self):
        """Verify login with correct credentials creates session and redirects."""
        # Register user
        self.client.post('/register', data={
            'name': 'Login Tester', 'email': 'login@example.com',
            'password': 'CorrectPassword123!', 'confirm_password': 'CorrectPassword123!'
        })

        # Login
        response = self.client.post('/login', data={
            'email': 'login@example.com',
            'password': 'CorrectPassword123!'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome back, Login Tester!", response.data)
        self.assertIn(b"Authenticated Session Active", response.data)

    def test_07_invalid_password_login_attempt(self):
        """Verify login rejection with incorrect password."""
        self.client.post('/register', data={
            'name': 'Login Tester', 'email': 'user@example.com',
            'password': 'CorrectPassword123!', 'confirm_password': 'CorrectPassword123!'
        })

        response = self.client.post('/login', data={
            'email': 'user@example.com',
            'password': 'WrongPassword123!'
        })
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid email or password", response.data)

    def test_08_nonexistent_user_login(self):
        """Verify login rejection for non-existent email."""
        response = self.client.post('/login', data={
            'email': 'ghost@example.com',
            'password': 'SomePassword123!'
        })
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid email or password", response.data)

    # -------------------------------------------------------------
    # 3. Rate Limiting Tests
    # -------------------------------------------------------------
    def test_09_rate_limiting_lockout(self):
        """Verify that 5 failed attempts trigger rate-limiting HTTP 429 lockout."""
        email = 'target@example.com'
        for i in range(5):
            res = self.client.post('/login', data={'email': email, 'password': 'WrongPassword!'})
            self.assertEqual(res.status_code, 401)

        # 6th attempt should be blocked with 429 Too Many Requests
        blocked_res = self.client.post('/login', data={'email': email, 'password': 'WrongPassword!'})
        self.assertEqual(blocked_res.status_code, 429)
        self.assertIn(b"Too many failed login attempts", blocked_res.data)

    # -------------------------------------------------------------
    # 4. SQL Injection Protection Tests
    # -------------------------------------------------------------
    def test_10_sql_injection_defense(self):
        """Verify that SQL injection payloads are neutralized by parameterized queries."""
        # SQL injection payloads
        injection_payloads = [
            "' OR '1'='1",
            "admin' --",
            "' UNION SELECT id, name, email, password_hash, 1, 0, NULL, NULL, NULL, NULL, NULL FROM users --",
            "test'; DROP TABLE users; --"
        ]

        for payload in injection_payloads:
            res = self.client.post('/login', data={'email': payload, 'password': 'AnyPassword123!'})
            # Must return 401 Unauthorized or 400 Bad Request, never 200 or 500 error
            self.assertIn(res.status_code, (400, 401))

        # Check users table still exists and is intact
        users_count = fetch_one("SELECT count(*) as cnt FROM users", (), self.db_path)
        self.assertIsNotNone(users_count)

    # -------------------------------------------------------------
    # 5. Session Management & Unauthorized Access Tests
    # -------------------------------------------------------------
    def test_11_unauthorized_dashboard_access_redirects(self):
        """Verify unauthenticated requests to protected dashboard are redirected to login."""
        response = self.client.get('/dashboard', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please log in to access this page", response.data)

    def test_12_logout_invalidates_session(self):
        """Verify that logout destroys active session and redirects safely."""
        # Register and login
        self.client.post('/register', data={
            'name': 'Session User', 'email': 'session@example.com',
            'password': 'StrongPassword123!', 'confirm_password': 'StrongPassword123!'
        })
        self.client.post('/login', data={
            'email': 'session@example.com', 'password': 'StrongPassword123!'
        })

        # Confirm dashboard is accessible
        dash_res = self.client.get('/dashboard')
        self.assertEqual(dash_res.status_code, 200)

        # Logout
        logout_res = self.client.post('/logout', follow_redirects=True)
        self.assertEqual(logout_res.status_code, 200)
        self.assertIn(b"You have been logged out securely", logout_res.data)

        # Confirm dashboard is no longer accessible
        dash_after_logout = self.client.get('/dashboard', follow_redirects=True)
        self.assertIn(b"Please log in to access this page", dash_after_logout.data)

    # -------------------------------------------------------------
    # 6. Two-Factor Authentication (2FA) Lifecycle Tests
    # -------------------------------------------------------------
    def test_13_two_factor_authentication_workflow(self):
        """Verify complete 2FA setup, challenge during login, and backup codes."""
        # 1. Register & login user
        self.client.post('/register', data={
            'name': 'TwoFactor User', 'email': '2fa@example.com',
            'password': 'SecurePassword123!', 'confirm_password': 'SecurePassword123!'
        })
        self.client.post('/login', data={
            'email': '2fa@example.com', 'password': 'SecurePassword123!'
        })

        # 2. Get 2FA setup page (generates temporary secret in session)
        setup_get = self.client.get('/security/2fa/setup')
        self.assertEqual(setup_get.status_code, 200)
        self.assertIn(b"Enable Two-Factor Authentication", setup_get.data)

        # Retrieve secret from session
        with self.client.session_transaction() as sess:
            secret = sess.get('temp_totp_secret')
            backup_codes = sess.get('temp_backup_codes_plain')

        self.assertIsNotNone(secret)
        self.assertIsNotNone(backup_codes)

        # 3. Generate valid TOTP token using pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Submit code to confirm 2FA activation
        setup_post = self.client.post('/security/2fa/setup', data={'totp_code': valid_code}, follow_redirects=True)
        self.assertEqual(setup_post.status_code, 200)
        self.assertIn(b"Two-Factor Authentication has been successfully enabled", setup_post.data)

        # Check DB shows 2FA enabled
        user = fetch_one("SELECT * FROM users WHERE email = ?", ('2fa@example.com',), self.db_path)
        self.assertEqual(user['is_2fa_enabled'], 1)
        self.assertEqual(user['totp_secret'], secret)

        # 4. Logout
        self.client.post('/logout')

        # 5. Login attempt with password - should redirect to 2FA challenge page!
        login_res = self.client.post('/login', data={
            'email': '2fa@example.com', 'password': 'SecurePassword123!'
        }, follow_redirects=True)
        self.assertIn(b"Enter 6-Digit Authenticator Code", login_res.data)

        # Attempting to access dashboard before 2FA token should fail
        dash_res = self.client.get('/dashboard', follow_redirects=True)
        self.assertIn(b"Please log in to access this page", dash_res.data)

        # 6. Submit invalid 2FA code
        invalid_2fa = self.client.post('/login/2fa', data={'totp_code': '000000'})
        self.assertEqual(invalid_2fa.status_code, 401)
        self.assertIn(b"Invalid two-factor authentication code", invalid_2fa.data)

        # 7. Submit valid 2FA code
        fresh_code = totp.now()
        valid_2fa = self.client.post('/login/2fa', data={'totp_code': fresh_code}, follow_redirects=True)
        self.assertEqual(valid_2fa.status_code, 200)
        self.assertIn(b"Two-Factor Authentication confirmed", valid_2fa.data)
        self.assertIn(b"Welcome back, TwoFactor User!", valid_2fa.data)

        # 8. Test backup recovery code authentication
        # Logout again
        self.client.post('/logout')
        self.client.post('/login', data={'email': '2fa@example.com', 'password': 'SecurePassword123!'})

        # Use one of the backup recovery codes
        first_backup_code = backup_codes[0]
        backup_auth = self.client.post('/login/2fa', data={'backup_code': first_backup_code}, follow_redirects=True)
        self.assertEqual(backup_auth.status_code, 200)
        self.assertIn(b"Two-Factor Authentication confirmed", backup_auth.data)

        # Verify the used backup code is consumed and cannot be reused
        self.client.post('/logout')
        self.client.post('/login', data={'email': '2fa@example.com', 'password': 'SecurePassword123!'})
        reuse_res = self.client.post('/login/2fa', data={'backup_code': first_backup_code})
        self.assertEqual(reuse_res.status_code, 401)

if __name__ == '__main__':
    unittest.main(verbosity=2)
