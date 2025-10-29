# A02: Cryptographic Failures - Flask SQLite Example

## Overview
This directory contains a Flask API demonstrating common cryptographic failures using SQLite database storage. The example shows both vulnerable and secure implementations side-by-side.

## Vulnerabilities Demonstrated

### 1. Weak Password Hashing - `/register` endpoint

**Vulnerable Code:**
```python
@app.route('/register', methods=['POST'])
def register():
    """User registration with weak MD5 password hashing."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    # Vulnerable: MD5 password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            (username, password_hash, email)
        )
        conn.commit()
        return jsonify({'message': 'User registered', 'hash': password_hash})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username exists'}), 400
    finally:
        conn.close()
```

**Issues:**
- **MD5 is cryptographically broken** - vulnerable to collision attacks
- **No salt** - same passwords produce same hashes (rainbow table attacks)
- **Fast hashing** - allows billions of brute force attempts per second
- **Hash exposed** - returns the hash in response (information leakage)

**Attack Example:**
```bash
# Register user - MD5 hash is predictable and weak
curl -X POST http://localhost:5002/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"victim","password":"password123","email":"victim@example.com"}'

# Response shows MD5 hash: "482c811da5d5b4bc6d497ffa98491e38"
# This hash can be cracked in seconds using online tools
```

### 2. Weak Login Verification - `/login` endpoint

**Vulnerable Code:**
```python
@app.route('/login', methods=['POST'])
def login():
    """Login with weak password verification."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Vulnerable: MD5 comparison
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id FROM users WHERE username = ? AND password = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'message': 'Login successful', 'user_id': user[0]})
    return jsonify({'error': 'Invalid credentials'}), 401
```

**Issues:**
- **Same weak MD5 hashing** for password verification
- **Timing attacks possible** - different response times for existing vs non-existing users
- **No rate limiting** - allows unlimited brute force attempts

### 3. Weak Data Encryption - `/profile/<id>` endpoint

**Vulnerable Code:**
```python
@app.route('/profile/<int:user_id>')
def get_profile(user_id):
    """Get user profile with weak encryption."""
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT username, email, credit_card FROM users WHERE id = ?',
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        username, email, encrypted_cc = user
        # Vulnerable: Simple base64 "encryption"
        credit_card = base64.b64decode(encrypted_cc).decode() if encrypted_cc else None
        
        return jsonify({
            'username': username,
            'email': email,
            'credit_card': credit_card  # Sensitive data exposed!
        })
    return jsonify({'error': 'User not found'}), 404
```

**Issues:**
- **Base64 is encoding, not encryption** - easily reversible
- **No key required** - anyone can decode the data
- **Sensitive data exposure** - credit card numbers shown in plain text
- **No access control** - any user ID can be accessed

**Database Initialization with Weak Crypto:**
```python
# Sample users with weak crypto in database
sample_users = [
    ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@example.com', 
     base64.b64encode('4532-1234-5678-9012'.encode()).decode()),
    ('alice', hashlib.md5('password'.encode()).hexdigest(), 'alice@example.com', 
     base64.b64encode('5555-4444-3333-2222'.encode()).decode())
]
```

## Secure Solutions

### 1. Strong Password Hashing - `/secure/register` endpoint

**Secure Code:**
```python
@app.route('/secure/register', methods=['POST'])
def secure_register():
    """Secure user registration with bcrypt."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    # Secure: bcrypt password hashing
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO secure_users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, password_hash.decode('utf-8'), email)
        )
        conn.commit()
        return jsonify({'message': 'User registered securely'})  # No hash exposed
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username exists'}), 400
    finally:
        conn.close()
```

**Improvements:**
- **bcrypt with salt** - each password gets unique salt automatically
- **Adaptive hashing** - computationally expensive to crack
- **No hash exposure** - doesn't return hash in response
- **Future-proof** - can increase cost factor as hardware improves

### 2. Secure Login Verification - `/secure/login` endpoint

**Secure Code:**
```python
@app.route('/secure/login', methods=['POST'])
def secure_login():
    """Secure login with bcrypt verification."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, password_hash FROM secure_users WHERE username = ?',
        (username,)
    )
    user = cursor.fetchone()
    conn.close()
    
    # Secure: bcrypt password verification with constant-time comparison
    if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        return jsonify({'message': 'Login successful', 'user_id': user[0]})
    return jsonify({'error': 'Invalid credentials'}), 401
```

**Improvements:**
- **bcrypt.checkpw()** - secure password verification
- **Constant-time comparison** - prevents timing attacks
- **Proper error handling** - same response for all failure cases

### 3. Strong Data Encryption - `/secure/profile/<id>` endpoint

**Secure Code:**
```python
@app.route('/secure/profile/<int:user_id>')
def secure_get_profile(user_id):
    """Get user profile with strong encryption."""
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT username, email, credit_card FROM secure_users WHERE id = ?',
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        username, email, encrypted_cc = user
        # Secure: Fernet encryption/decryption
        credit_card = None
        if encrypted_cc:
            try:
                credit_card = secure_crypto.fernet.decrypt(encrypted_cc.encode()).decode()
            except:
                credit_card = "Decryption failed"  # Safe error handling
        
        return jsonify({
            'username': username,
            'email': email,
            'credit_card': credit_card
        })
    return jsonify({'error': 'User not found'}), 404
```

**Secure Encryption Implementation:**
```python
class CryptographicSolutions:
    """Secure implementations that fix cryptographic failures."""
    
    def __init__(self):
        # Generate secure random key for Fernet (AES-128 in CBC mode)
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.secure_db = "users_secure.db"
        self.init_secure_database()
```

**Secure Payment Update:**
```python
@app.route('/secure/update_payment', methods=['POST'])
def secure_update_payment():
    """Update payment info with strong encryption."""
    data = request.get_json()
    user_id = data.get('user_id')
    credit_card = data.get('credit_card')
    
    # Secure: Fernet encryption (AES + HMAC)
    encrypted_cc = secure_crypto.fernet.encrypt(credit_card.encode()).decode()
    
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE secure_users SET credit_card = ? WHERE id = ?',
        (encrypted_cc, user_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Payment info updated securely'})
```

**Improvements:**
- **Fernet encryption** - uses AES-128 in CBC mode with HMAC-SHA256
- **Authenticated encryption** - prevents tampering
- **Random key generation** - cryptographically secure keys
- **Proper error handling** - doesn't leak encryption details

## Testing the Vulnerabilities

### Test Weak Crypto:
```bash
# 1. Register with weak MD5 - hash is predictable
curl -X POST http://localhost:5002/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"password123","email":"test@example.com"}'

# 2. Login with MD5 verification
curl -X POST http://localhost:5002/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"password123"}'

# 3. View profile - credit card in base64 (easily decoded)
curl http://localhost:5002/profile/1
```

### Test Strong Crypto:
```bash
# 1. Register with bcrypt - secure hashing
curl -X POST http://localhost:5002/secure/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"secure","password":"SecurePass123","email":"secure@example.com"}'

# 2. Login with bcrypt verification
curl -X POST http://localhost:5002/secure/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"secure","password":"SecurePass123"}'

# 3. Update payment with strong encryption
curl -X POST http://localhost:5002/secure/update_payment \
  -H 'Content-Type: application/json' \
  -d '{"user_id":1,"credit_card":"1234-5678-9012-3456"}'

# 4. View profile - credit card properly encrypted
curl http://localhost:5002/secure/profile/1
```

## Key Differences Summary

| Aspect | Vulnerable Implementation | Secure Implementation |
|--------|---------------------------|----------------------|
| **Password Hashing** | `hashlib.md5()` - no salt | `bcrypt.hashpw()` - with salt |
| **Password Verification** | MD5 comparison | `bcrypt.checkpw()` |
| **Data Encryption** | `base64.b64encode()` | `fernet.encrypt()` (AES) |
| **Key Management** | No keys needed | Secure random key generation |
| **Database** | `users_crypto.db` | `users_secure.db` |
| **Error Handling** | Exposes internal details | Safe generic messages |

## Running the Example

```bash
# Start the server
python A02_Example_Cryptographic_Failures.py

# Server runs on http://localhost:5002
# Test both vulnerable and secure endpoints
```

---
**⚠️ WARNING: Contains intentional vulnerabilities for educational purposes only!**