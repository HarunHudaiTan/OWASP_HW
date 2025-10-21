# A07: Identification and Authentication Failures - Detailed Analysis

## Overview
This directory contains examples of identification and authentication failures as outlined in the OWASP Top 10 2021 - A07 Identification and Authentication Failures.

Failures in authentication mechanisms can allow attackers to compromise passwords, keys, or session tokens, or exploit other implementation flaws to assume other users' identities.

## Vulnerabilities Demonstrated

### 1. `register()` - Weak Password Policy

**Vulnerable Code:**
```python
@app.route('/register', methods=['POST'])
def register():
    """Register new user with weak password policy."""
    username = request.json['username']
    password = request.json['password']
    
    # No password strength requirements
    if len(password) < 3:  # Very weak requirement
        return jsonify({"error": "Password too short"}), 400
    
    users[username] = password
    return jsonify({"message": "User registered"})
```

**Vulnerabilities Present:**
- **CWE-521: Weak Password Requirements**
- **CWE-256: Unprotected Storage of Credentials**

**Issues:**
1. **Extremely Weak Password Policy**: Only requires 3 characters
2. **No Complexity Requirements**: No uppercase, numbers, or special characters
3. **Plaintext Storage**: Passwords stored without hashing
4. **No Username Validation**: Allows duplicate usernames

**Secure Solution:**
```python
import re
import bcrypt
from datetime import datetime

def validate_password(password):
    """Comprehensive password validation"""
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Check against common passwords
    common_passwords = ['password', '123456', 'qwerty', 'admin']
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    return errors

@app.route('/register_secure', methods=['POST'])
def register_secure():
    """Secure user registration with strong password policy"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    # Username validation
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return jsonify({"error": "Username must be 3-20 alphanumeric characters"}), 400
    
    if username in users:
        return jsonify({"error": "Username already exists"}), 409
    
    # Password validation
    password_errors = validate_password(password)
    if password_errors:
        return jsonify({"error": "Password requirements not met", "details": password_errors}), 400
    
    # Hash password securely
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    # Store user with metadata
    users[username] = {
        'password_hash': password_hash.decode('utf-8'),
        'created_at': datetime.utcnow().isoformat(),
        'failed_attempts': 0,
        'locked_until': None,
        'last_login': None
    }
    
    logger.info(f"User registered: {username}")
    
    return jsonify({"message": "User registered successfully"}), 201
```

### 2. `login()` - Missing Rate Limiting and Account Lockout

**Vulnerable Code:**
```python
@app.route('/login', methods=['POST'])
def login():
    """Login with weak authentication."""
    username = request.json['username']
    password = request.json['password']
    
    # No rate limiting or account lockout
    if username in users and users[username] == password:
        session['user'] = username
        return jsonify({"message": "Login successful"})
    else:
        # Track failed attempts but don't act on them
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        return jsonify({"error": "Invalid credentials"}), 401
```

**Vulnerabilities Present:**
- **CWE-307: Improper Restriction of Excessive Authentication Attempts**
- **CWE-308: Use of Single-factor Authentication**

**Issues:**
1. **No Rate Limiting**: Unlimited login attempts allowed
2. **No Account Lockout**: No protection against brute force attacks
3. **Information Disclosure**: Different responses for valid/invalid usernames
4. **Weak Session Management**: Basic session handling

**Secure Solution:**
```python
from datetime import datetime, timedelta
import time
import secrets

# Rate limiting storage (use Redis in production)
login_attempts = {}
locked_accounts = {}

def is_account_locked(username):
    """Check if account is currently locked"""
    if username in locked_accounts:
        lock_time = locked_accounts[username]
        if datetime.utcnow() < lock_time:
            return True
        else:
            # Lock expired, remove it
            del locked_accounts[username]
    return False

def record_failed_attempt(username, ip_address):
    """Record failed login attempt"""
    now = datetime.utcnow()
    key = f"{username}:{ip_address}"
    
    if key not in login_attempts:
        login_attempts[key] = []
    
    # Clean old attempts (older than 15 minutes)
    login_attempts[key] = [
        attempt for attempt in login_attempts[key]
        if now - attempt < timedelta(minutes=15)
    ]
    
    login_attempts[key].append(now)
    
    # Lock account after 5 failed attempts
    if len(login_attempts[key]) >= 5:
        locked_accounts[username] = now + timedelta(minutes=30)
        logger.warning(f"Account locked due to failed attempts: {username} from {ip_address}")
        return True
    
    return False

@app.route('/login_secure', methods=['POST'])
def login_secure():
    """Secure login with rate limiting and account lockout"""
    data = request.get_json()
    ip_address = request.remote_addr
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    # Check if account is locked
    if is_account_locked(username):
        logger.warning(f"Login attempt on locked account: {username} from {ip_address}")
        return jsonify({"error": "Account temporarily locked"}), 423
    
    # Rate limiting check
    if is_rate_limited(ip_address):
        return jsonify({"error": "Too many requests"}), 429
    
    # Authenticate user
    if username in users:
        user_data = users[username]
        stored_hash = user_data['password_hash'].encode('utf-8')
        
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            # Successful login
            session['user_id'] = username
            session['login_time'] = datetime.utcnow().isoformat()
            session['csrf_token'] = secrets.token_hex(16)
            
            # Update user data
            users[username]['last_login'] = datetime.utcnow().isoformat()
            users[username]['failed_attempts'] = 0
            
            # Clear failed attempts
            key = f"{username}:{ip_address}"
            if key in login_attempts:
                del login_attempts[key]
            
            logger.info(f"Successful login: {username} from {ip_address}")
            
            return jsonify({
                "message": "Login successful",
                "csrf_token": session['csrf_token']
            })
    
    # Failed login
    account_locked = record_failed_attempt(username, ip_address)
    logger.warning(f"Failed login attempt: {username} from {ip_address}")
    
    # Always return same message (don't reveal if username exists)
    if account_locked:
        return jsonify({"error": "Account temporarily locked due to multiple failed attempts"}), 423
    else:
        return jsonify({"error": "Invalid credentials"}), 401

def is_rate_limited(ip_address):
    """Check if IP is rate limited"""
    # Implement IP-based rate limiting
    # Allow 10 requests per minute per IP
    return False  # Simplified for demo
```

### 3. `reset_password()` - Insecure Password Reset

**Vulnerable Code:**
```python
@app.route('/reset_password', methods=['POST'])
def reset_password():
    """Reset password with weak verification."""
    username = request.json['username']
    
    # No proper identity verification
    if username in users:
        new_password = "temp123"  # Predictable temporary password
        users[username] = new_password
        return jsonify({"message": f"Password reset to: {new_password}"})
    
    return jsonify({"error": "User not found"}), 404
```

**Vulnerabilities Present:**
- **CWE-640: Weak Password Recovery Mechanism**
- **CWE-200: Information Exposure**

**Issues:**
1. **No Identity Verification**: No email or security questions
2. **Predictable Passwords**: Same temporary password for everyone
3. **Information Disclosure**: Reveals if username exists
4. **No Secure Delivery**: Password sent in response

**Secure Solution:**
```python
import secrets
import smtplib
from email.mime.text import MIMEText

# Password reset tokens (use Redis with TTL in production)
reset_tokens = {}

@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    """Secure password reset request"""
    data = request.get_json()
    
    if not data or 'email' not in data:
        return jsonify({"error": "Email address required"}), 400
    
    email = data['email'].strip().lower()
    
    # Always return success to prevent username enumeration
    response_message = "If an account with that email exists, a password reset link has been sent."
    
    # Find user by email (in real app, store email separately)
    user_found = None
    for username, user_data in users.items():
        if user_data.get('email') == email:
            user_found = username
            break
    
    if user_found:
        # Generate secure reset token
        reset_token = secrets.token_urlsafe(32)
        reset_tokens[reset_token] = {
            'username': user_found,
            'expires': datetime.utcnow() + timedelta(hours=1),
            'used': False
        }
        
        # Send reset email (implement actual email sending)
        send_password_reset_email(email, reset_token)
        
        logger.info(f"Password reset requested for: {user_found}")
    
    return jsonify({"message": response_message})

@app.route('/reset_password_secure', methods=['POST'])
def reset_password_secure():
    """Complete password reset with token verification"""
    data = request.get_json()
    
    if not data or 'token' not in data or 'new_password' not in data:
        return jsonify({"error": "Token and new password required"}), 400
    
    token = data['token']
    new_password = data['new_password']
    
    # Validate token
    if token not in reset_tokens:
        return jsonify({"error": "Invalid or expired reset token"}), 400
    
    token_data = reset_tokens[token]
    
    # Check if token is expired or used
    if (datetime.utcnow() > token_data['expires'] or 
        token_data['used']):
        del reset_tokens[token]
        return jsonify({"error": "Invalid or expired reset token"}), 400
    
    username = token_data['username']
    
    # Validate new password
    password_errors = validate_password(new_password)
    if password_errors:
        return jsonify({"error": "Password requirements not met", "details": password_errors}), 400
    
    # Update password
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    
    users[username]['password_hash'] = password_hash.decode('utf-8')
    users[username]['failed_attempts'] = 0
    
    # Mark token as used
    token_data['used'] = True
    
    # Invalidate all sessions for this user
    invalidate_user_sessions(username)
    
    logger.info(f"Password reset completed for: {username}")
    
    return jsonify({"message": "Password reset successfully"})

def send_password_reset_email(email, token):
    """Send password reset email (implement with actual email service)"""
    reset_url = f"https://yourapp.com/reset?token={token}"
    
    # In production, use proper email service
    logger.info(f"Password reset email would be sent to {email} with URL: {reset_url}")

def invalidate_user_sessions(username):
    """Invalidate all sessions for a user"""
    # In production, implement proper session invalidation
    pass
```

## Multi-Factor Authentication Implementation

```python
import pyotp
import qrcode
from io import BytesIO
import base64

@app.route('/setup_mfa', methods=['POST'])
@require_auth
def setup_mfa():
    """Set up multi-factor authentication"""
    username = session['user_id']
    
    # Generate secret key
    secret = pyotp.random_base32()
    
    # Store secret (encrypt in production)
    users[username]['mfa_secret'] = secret
    users[username]['mfa_enabled'] = False
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="Secure App"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    
    return jsonify({
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_code}"
    })

@app.route('/verify_mfa', methods=['POST'])
@require_auth
def verify_mfa():
    """Verify and enable MFA"""
    data = request.get_json()
    username = session['user_id']
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "MFA token required"}), 400
    
    secret = users[username].get('mfa_secret')
    if not secret:
        return jsonify({"error": "MFA not set up"}), 400
    
    # Verify token
    totp = pyotp.TOTP(secret)
    if totp.verify(token, valid_window=1):
        users[username]['mfa_enabled'] = True
        logger.info(f"MFA enabled for user: {username}")
        return jsonify({"message": "MFA enabled successfully"})
    else:
        return jsonify({"error": "Invalid MFA token"}), 400
```

## Prevention Strategies

1. **Strong Password Policies**: Enforce complex, unique passwords
2. **Multi-Factor Authentication**: Implement MFA for all accounts
3. **Account Lockout**: Protect against brute force attacks
4. **Rate Limiting**: Limit authentication attempts per IP/user
5. **Secure Session Management**: Use secure session tokens
6. **Password Reset Security**: Implement secure password recovery
7. **Regular Security Audits**: Monitor authentication logs

## References
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---
**⚠️ WARNING: The code in this directory contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**
