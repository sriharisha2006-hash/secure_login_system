import re
import io
import base64
import secrets
import string
import json
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import pyotp
import qrcode
from config import Config

# Initialize Argon2 hasher with secure parameters
argon2_hasher = PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,      # 4 threads
    hash_len=32,
    salt_len=16
)

# -------------------------------------------------------------
# Password Hashing & Verification
# -------------------------------------------------------------

def hash_password(password: str, algo: str = None) -> str:
    """
    Hash a password securely using either bcrypt or Argon2.
    Salt is generated cryptographically automatically by both libraries.
    Plain-text is never stored.
    """
    algorithm = (algo or Config.DEFAULT_HASH_ALGO).lower()
    
    if algorithm == 'argon2':
        return argon2_hasher.hash(password)
    
    # Default: bcrypt (cost factor = 12)
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_bytes.decode('utf-8')

def verify_password(password: str, stored_hash: str, algo: str = None) -> bool:
    """
    Verify a plain password against the stored secure hash.
    Uses constant-time comparison internally to prevent timing attacks.
    """
    if not password or not stored_hash:
        return False
        
    algorithm = (algo or Config.DEFAULT_HASH_ALGO).lower()
    
    # Auto-detect algorithm if hash format is recognized
    if stored_hash.startswith('$argon2'):
        try:
            return argon2_hasher.verify(stored_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False
        except Exception:
            return False
            
    if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$') or stored_hash.startswith('$2y$'):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            return False
            
    # Fallback to designated algo
    if algorithm == 'argon2':
        try:
            return argon2_hasher.verify(stored_hash, password)
        except Exception:
            return False
    else:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            return False

# -------------------------------------------------------------
# Input Validation & Sanitization
# -------------------------------------------------------------

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

def validate_email(email: str) -> tuple[bool, str, str]:
    """
    Validate and normalize email address.
    Returns: (is_valid, normalized_email, error_message)
    """
    if not email or not isinstance(email, str):
        return False, "", "Email address is required."
        
    email = email.strip().lower()
    
    if len(email) > 254:
        return False, "", "Email address is too long (maximum 254 characters)."
        
    if not EMAIL_REGEX.match(email):
        return False, "", "Please enter a valid email address (e.g., user@example.com)."
        
    return True, email, ""

def validate_name(name: str) -> tuple[bool, str, str]:
    """
    Validate and sanitize user display name.
    Returns: (is_valid, sanitized_name, error_message)
    """
    if not name or not isinstance(name, str):
        return False, "", "Full name is required."
        
    name = " ".join(name.strip().split()) # Normalize whitespace
    
    if len(name) < 2:
        return False, "", "Name must be at least 2 characters long."
        
    if len(name) > 60:
        return False, "", "Name cannot exceed 60 characters."
        
    # Check for disallowed characters (allow letters, spaces, hyphens, apostrophes)
    if not re.match(r"^[A-Za-z\s'\-]+$", name):
        return False, "", "Name can only contain letters, spaces, hyphens, and apostrophes."
        
    return True, name, ""

def validate_password_strength(password: str) -> tuple[bool, list[str], int]:
    """
    Validate password against security policy requirements:
    - Minimum length (8 characters)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special symbol
    Returns: (is_valid, errors_list, score_0_to_100)
    """
    errors = []
    score = 0
    
    if not password or not isinstance(password, str):
        return False, ["Password is required."], 0
        
    # Length evaluation
    length = len(password)
    if length < Config.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {Config.PASSWORD_MIN_LENGTH} characters long.")
    elif length >= 12:
        score += 35
    elif length >= 10:
        score += 25
    else:
        score += 15
        
    # Uppercase check
    if Config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")
    else:
        score += 15
        
    # Lowercase check
    if Config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter (a-z).")
    else:
        score += 15
        
    # Digit check
    if Config.PASSWORD_REQUIRE_DIGIT and not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one numeric digit (0-9).")
    else:
        score += 20
        
    # Special character check
    if Config.PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        errors.append("Password must contain at least one special character (!@#$%^&*...).")
    else:
        score += 15
        
    score = min(100, score)
    return len(errors) == 0, errors, score

# -------------------------------------------------------------
# Two-Factor Authentication (TOTP)
# -------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a high-entropy base32 secret for TOTP."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str, issuer: str = "SecureAuth Portal") -> str:
    """Generate the standardized otpauth:// URI for authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)

def generate_qr_code_base64(uri: str) -> str:
    """
    Generate a high-contrast QR code image as a base64 Data URL.
    Can be rendered directly in an <img src="..."> tag without external requests.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="#1E3A8A", back_color="#FFFFFF")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_b64}"

def verify_totp_token(secret: str, token: str) -> bool:
    """
    Verify user-provided 6-digit TOTP token against secret.
    Allows 1 time step drift (30 seconds before/after) to account for clock skew.
    """
    if not secret or not token:
        return False
        
    clean_token = token.strip().replace(" ", "").replace("-", "")
    if len(clean_token) != 6 or not clean_token.isdigit():
        return False
        
    totp = pyotp.TOTP(secret)
    return totp.verify(clean_token, valid_window=1)

def generate_backup_codes(count: int = 8) -> tuple[list[str], list[str]]:
    """
    Generate recovery backup codes.
    Returns:
      plain_codes: list of strings (shown once to user)
      hashed_codes: list of hashed strings (stored in DB)
    """
    plain_codes = []
    hashed_codes = []
    
    charset = string.ascii_uppercase + string.digits
    for _ in range(count):
        part1 = ''.join(secrets.choice(charset) for _ in range(4))
        part2 = ''.join(secrets.choice(charset) for _ in range(4))
        code = f"{part1}-{part2}"
        plain_codes.append(code)
        
        # Salted hash of backup code
        code_hash = bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt(rounds=10)).decode('utf-8')
        hashed_codes.append(code_hash)
        
    return plain_codes, hashed_codes

def verify_and_consume_backup_code(plain_code: str, stored_codes_json: str) -> tuple[bool, str]:
    """
    Verify if a backup code matches one of the stored hashes.
    If match found, removes the used code and returns (True, updated_json).
    Otherwise returns (False, stored_codes_json).
    """
    if not stored_codes_json or not plain_code:
        return False, stored_codes_json
        
    try:
        hashed_list = json.loads(stored_codes_json)
    except Exception:
        return False, stored_codes_json
        
    clean_code = plain_code.strip().upper()
    
    for idx, stored_hash in enumerate(hashed_list):
        try:
            if bcrypt.checkpw(clean_code.encode('utf-8'), stored_hash.encode('utf-8')):
                # Remove consumed code
                hashed_list.pop(idx)
                return True, json.dumps(hashed_list)
        except Exception:
            continue
            
    return False, stored_codes_json
