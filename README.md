# Secure Login System (SecureAuth Portal)

A complete, production-ready **Secure Login System Web Application** engineered with enterprise-grade authentication standards, modern cryptographic defenses, session security, and a sleek blue/white/light-gradient responsive interface.

---

## Key Features & Security Architecture

### 1. Robust User Registration
- **Password Hashing**: Passwords are never stored in plain-text. Users or administrators can choose between **Bcrypt** (12-round key stretching) or **Argon2id** (memory-hard winner of the Password Hashing Competition).
- **Password Policy Enforcement**: Real-time validation requiring at least 8 characters, uppercase and lowercase letters, numeric digits, and special characters.
- **Interactive Password Strength Meter**: Live client-side checklist and color-coded strength score, backed by strict server-side validation.
- **Duplicate Prevention**: Case-insensitive email checking using parameterized SQL queries.

### 2. Secure User Authentication & Login
- **Constant-Time Hash Verification**: Mitigates timing side-channel attacks during password evaluation.
- **Generic Error Messaging**: Prevents user enumeration attacks by returning consistent "Invalid email or password" messages.
- **Automatic Brute Force Defense**: Rate limiting tracks failed attempts per IP and per account.
- **Temporary Lockout**: Blocks repeated failures (5 attempts per 5 minutes) with a real-time countdown timer.

### 3. Two-Factor Authentication (2FA / TOTP)
- **Standard TOTP Protocol**: Compatible with Google Authenticator, Microsoft Authenticator, Authy, and 1Password.
- **Inline QR Code Generation**: Self-contained Base64 QR code rendering (zero external CDN or 3rd-party dependencies).
- **Manual Secret Key**: Base32 secret with 1-click copy for manual entry.
- **Emergency Recovery Codes**: Generates 8 one-time cryptographic backup codes for recovery when device is lost. Each backup code is single-use and burned upon consumption.
- **Secure 2FA Deactivation**: Requires user password verification before disabling 2FA.

### 4. Input Validation & SQL Injection Defense
- **Dual-Layer Validation**: Frontend real-time feedback paired with strict backend schema validation.
- **100% Parameterized SQL Queries**: All database operations use `?` parameter placeholders with SQLite, neutralizing all SQL injection vectors (`' OR 1=1 --`, `UNION SELECT`, stacked queries).
- **XSS Sanitization**: Input normalization and HTML-escaping to prevent stored or reflected Cross-Site Scripting.

### 5. Advanced Session Security
- **HTTP-Only Cookies**: Protected from JavaScript access (`document.cookie`), neutralizing cookie-theft XSS exploits.
- **SameSite=Lax Protection**: Defends against Cross-Site Request Forgery (CSRF).
- **Session Fixation Defense**: Clears previous session data and regenerates high-entropy session tokens upon login.
- **Remote Active Session Tracking**: Stores active session state server-side in the database.
- **True Invalidation on Logout**: Completely removes session tokens from the server database and destroys client cookies.

### 6. Security Audit Logging & Dashboard
- **Security Audit Trail**: Logs all critical authentication events (`USER_REGISTRATION`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `2FA_ENABLED`, `2FA_DISABLED`, `LOGOUT`, `RATE_LIMIT_BLOCKED`) with IP addresses, timestamps, and user agents.
- **Transparent User Dashboard**: Displays profile details, security posture, active session details, and the user's recent security logs in real-time.

### 7. Modern UI / UX Design
- **Color Theme**: Blue, white, and light-gradient palette featuring glassmorphism cards and clean typography (`Plus Jakarta Sans`).
- **Interactive Micro-Interactions**: Password visibility toggles (eye icon), auto-dismissing flash alerts, and auto-submitting 2FA fields.
- **Responsive Layout**: Designed for mobile, tablet, and desktop viewports.

---

## Project Structure

```
security login system/
├── app.py                     # Application entry point, routing, security headers & error handlers
├── config.py                  # Environment-driven security configuration
├── database.py                # Database connection manager, schema initialization & parameterized query layer
├── auth.py                    # Bcrypt & Argon2 hashing, password strength validation, TOTP 2FA engine
├── security.py                # Rate limiting, CSRF verification, session tracking & audit logging
├── requirements.txt           # Python library dependencies
├── run.bat                    # One-click Windows CMD launcher
├── run.ps1                    # One-click Windows PowerShell launcher
├── .env.example               # Environment variables template
├── static/
│   ├── css/
│   │   └── style.css          # Blue/white gradient theme & responsive styling
│   └── js/
│       └── main.js            # Password toggles, strength meter, countdown timers & notifications
├── templates/
│   ├── base.html              # Base layout with navbar, alerts, footer & security badge
│   ├── login.html             # Login view with rate-limit banner & password toggle
│   ├── register.html          # Registration view with real-time strength meter & algorithm selector
│   ├── two_factor.html        # 2FA challenge view with 6-digit input & backup code switch
│   ├── two_factor_setup.html  # 2FA setup with QR code, secret key & recovery codes
│   ├── dashboard.html         # User dashboard with account info, 2FA toggle & audit trail
│   └── error.html             # Styled error views (400, 403, 404, 429, 500)
└── tests/
    ├── test_secure_login.py           # 13 automated tests covering auth lifecycle & security
    └── test_security_headers_csrf.py  # 4 automated tests for security headers & CSRF protection
```

---

## Prerequisites

- **Python 3.9+** (Python 3.10, 3.11, 3.12, 3.13, 3.14 supported)
- Standard web browser (Chrome, Edge, Firefox, Safari)

---

## How to Run the Application Locally

### Option A: One-Click Windows Launch Script (Recommended)
Double-click `run.bat` or run in PowerShell:
```powershell
.\run.ps1
```

### Option B: Terminal Command
1. Open PowerShell or Command Prompt in the project folder:
   ```powershell
   cd "c:\Users\Admin'\OneDrive\Desktop\security login system"
   ```

2. Run the application:
   ```powershell
   python app.py
   ```
   *(Or specify your local Python interpreter: `& "$env:LOCALAPPDATA\Python\bin\python.exe" app.py`)*

3. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## Running the Automated Test Suite

A comprehensive test suite of **17 unit and integration tests** is included, testing:
- Bcrypt & Argon2 password registration and hashing
- Password complexity policy enforcement
- Duplicate email prevention
- Login authentication & incorrect password rejection
- Brute-force rate limiting (5 attempts threshold & 429 lockout)
- SQL injection resistance against standard injection payloads
- Session protection and unauthorized access prevention
- Full Two-Factor Authentication lifecycle (setup, TOTP verification, backup code usage)
- CSRF token validation and HTTP security headers

To execute all tests:
```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Expected output:
```
Ran 17 tests in ~8s
OK
```

---

## Security Verification Checklist

| Security Feature | Implementation | Verified Status |
| :--- | :--- | :---: |
| Password Hashing | Salted Bcrypt (cost 12) & Argon2id | **Verified** |
| SQL Injection Protection | 100% Parameterized SQL (`?` placeholders) | **Verified** |
| Rate Limiting | 5 failed attempts per 5 minutes per IP/Email | **Verified** |
| Session Security | HTTP-Only, SameSite=Lax, Server-Side Tracking | **Verified** |
| CSRF Protection | Cryptographic Double-Submit Token | **Verified** |
| Two-Factor Authentication | TOTP (RFC 6238) + 8 Hashed Emergency Backup Codes | **Verified** |
| Security Headers | CSP, X-Frame-Options (DENY), nosniff, Referrer-Policy | **Verified** |
| Audit Logging | Timestamped IP & User Agent Event Log | **Verified** |
