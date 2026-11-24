import os
import secrets
from datetime import timedelta

class Config:
    # Secret key for signing session cookies and CSRF tokens
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Database path
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or os.path.join(BASE_DIR, 'secure_login.db')
    
    # Session Security Configuration
    SESSION_COOKIE_NAME = '__Host_SecureSession' if os.environ.get('FLASK_ENV') == 'production' else 'secure_session'
    SESSION_COOKIE_HTTPONLY = True          # Prevent JavaScript access (mitigates XSS cookie theft)
    SESSION_COOKIE_SAMESITE = 'Lax'         # Mitigate CSRF while permitting top-level navigation
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1') # Set True when using HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2) # Automatic session expiration
    
    # Rate Limiting Configuration
    RATE_LIMIT_LOGIN_MAX_ATTEMPTS = int(os.environ.get('RATE_LIMIT_LOGIN_MAX_ATTEMPTS', 5))
    RATE_LIMIT_LOGIN_WINDOW_SECONDS = int(os.environ.get('RATE_LIMIT_LOGIN_WINDOW_SECONDS', 300)) # 5 minutes lockout
    
    # Password Policy Configuration
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True
    
    # Hashing Algorithm Choice: 'bcrypt' or 'argon2'
    DEFAULT_HASH_ALGO = os.environ.get('DEFAULT_HASH_ALGO', 'bcrypt')
    
    # App info
    APP_NAME = "SecureAuth Portal"
