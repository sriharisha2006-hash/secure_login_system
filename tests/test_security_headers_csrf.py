import os
import unittest
import tempfile
from app import app
from database import init_db

class SecurityHeadersAndCsrfTests(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        app.config['DATABASE_PATH'] = self.db_path
        app.config['TESTING'] = False  # Enable real CSRF checking
        app.config['WTF_CSRF_ENABLED'] = True
        self.client = app.test_client()

        with app.app_context():
            init_db(self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        try:
            os.remove(self.db_path)
        except Exception:
            pass

    def test_security_headers_present(self):
        """Verify presence of security headers on responses."""
        response = self.client.get('/login')
        headers = response.headers

        # Frame protection against clickjacking
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        # MIME sniffing protection
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        # Content Security Policy
        self.assertIn('Content-Security-Policy', headers)
        self.assertIn("default-src 'self'", headers['Content-Security-Policy'])
        # Referrer Policy
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')

    def test_csrf_token_required_for_post(self):
        """Verify POST requests without CSRF token are blocked with 403 Forbidden."""
        response = self.client.post('/login', data={
            'email': 'hacker@example.com',
            'password': 'AnyPassword123!'
        })
        self.assertEqual(response.status_code, 403)

    def test_tampered_csrf_token_rejected(self):
        """Verify POST requests with invalid CSRF token are blocked."""
        # Establish session to get a cookie
        self.client.get('/login')
        response = self.client.post('/login', data={
            'email': 'hacker@example.com',
            'password': 'AnyPassword123!',
            'csrf_token': 'fake_or_tampered_csrf_token_12345'
        })
        self.assertEqual(response.status_code, 403)

    def test_valid_csrf_token_accepted(self):
        """Verify POST requests with valid CSRF token from page are accepted."""
        # Get login page to extract CSRF token from HTML
        get_res = self.client.get('/login')
        html = get_res.data.decode('utf-8')
        
        # Extract CSRF token
        import re
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(match)
        valid_csrf = match.group(1)

        # Submit login form with valid CSRF token
        post_res = self.client.post('/login', data={
            'email': 'nobody@example.com',
            'password': 'WrongPassword123!',
            'csrf_token': valid_csrf
        })
        # Should be processed by the login controller (returning 401 for bad credentials), NOT blocked by CSRF 403!
        self.assertEqual(post_res.status_code, 401)

if __name__ == '__main__':
    unittest.main(verbosity=2)
