# A02: Cryptographic Failures - Detailed Analysis

## Overview
This directory contains examples of common cryptographic failures as outlined in the [OWASP Top 10 2021 - A02 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/).

## Vulnerabilities Demonstrated

### 1. `store_user_password()` - Weak Password Hashing

**Vulnerable Code:**
```python
def store_user_password(self, username, password):
    # Simple hash storage approach
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Store in a simple format
    with open(self.database_file, "a") as f:
        f.write(f"{username},{password_hash}\n")
    
    print(f"Password stored for user: {username}")
    return password_hash
```

**Vulnerabilities Present:**
- **CWE-327: Use of a Broken or Risky Cryptographic Algorithm**
- **CWE-759: Use of a One-Way Hash without a Salt**
- **CWE-916: Use of Password Hash With Insufficient Computational Effort**

**Issues:**
1. **MD5 Hash Function**: Uses MD5, which is cryptographically broken and vulnerable to collision attacks
2. **No Salt**: Passwords are hashed without salt, making them vulnerable to rainbow table attacks
3. **Fast Hashing**: MD5 is computationally fast, allowing brute force attacks with modern hardware
4. **Predictable Output**: Same passwords always produce the same hash

**Real-World Impact:**
- Attackers can use precomputed rainbow tables to crack common passwords instantly
- GPU-based attacks can crack MD5 hashes at billions of attempts per second
- Database breaches expose all user passwords immediately

**Secure Solution:**
```python
import bcrypt
import secrets

def store_user_password_secure(self, username, password):
    # Generate a random salt
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds = good security/performance balance
    
    # Hash password with salt using bcrypt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    # Store username and hash (salt is included in bcrypt hash)
    with open(self.database_file, "a") as f:
        f.write(f"{username},{password_hash.decode('utf-8')}\n")
    
    print(f"Password securely stored for user: {username}")
    return password_hash

def verify_password_secure(self, username, password, stored_hash):
    # Verify password against stored hash
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
```

**Why This Solution Works:**
- **bcrypt**: Adaptive hashing function designed for passwords
- **Built-in Salt**: Each hash includes a unique random salt
- **Work Factor**: Configurable rounds make brute force attacks expensive
- **Future-Proof**: Can increase rounds as hardware improves

### 2. `encrypt_sensitive_data()` - Weak Encryption Implementation

**Vulnerable Code:**
```python
def encrypt_sensitive_data(self, credit_card_number):
    # Simple encryption approach using base64
    encoded_data = base64.b64encode(credit_card_number.encode()).decode()
    
    # Additional layer using simple XOR with fixed key
    key = ord('K')  # Fixed key for simplicity
    encrypted = ""
    for char in encoded_data:
        encrypted += chr(ord(char) ^ key)
    
    final_encrypted = base64.b64encode(encrypted.encode()).decode()
    print(f"Credit card encrypted and stored safely!")
    return final_encrypted
```

**Vulnerabilities Present:**
- **CWE-327: Use of a Broken or Risky Cryptographic Algorithm**
- **CWE-321: Use of Hard-coded Cryptographic Key**
- **CWE-326: Inadequate Encryption Strength**

**Issues:**
1. **Base64 Encoding**: Base64 is encoding, not encryption - easily reversible
2. **XOR with Fixed Key**: Simple XOR cipher with a single-byte key is trivially breakable
3. **No Authentication**: No integrity protection - data can be modified without detection
4. **Predictable Key**: Fixed key 'K' provides no security

**Real-World Impact:**
- Credit card numbers can be decrypted by anyone with basic programming knowledge
- No protection against data tampering
- Regulatory compliance failures (PCI DSS violations)

**Secure Solution:**
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

def encrypt_sensitive_data_secure(self, credit_card_number, master_password):
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive key from master password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # High iteration count for security
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    # Create Fernet cipher (uses AES-128 in CBC mode with HMAC-SHA256)
    cipher = Fernet(key)
    
    # Encrypt the data
    encrypted_data = cipher.encrypt(credit_card_number.encode())
    
    # Store salt + encrypted data
    result = base64.b64encode(salt + encrypted_data).decode()
    print(f"Credit card securely encrypted!")
    return result

def decrypt_sensitive_data_secure(self, encrypted_data, master_password):
    # Decode the stored data
    data = base64.b64decode(encrypted_data.encode())
    
    # Extract salt and encrypted content
    salt = data[:16]
    encrypted_content = data[16:]
    
    # Recreate the key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    # Decrypt
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_content)
    return decrypted_data.decode()
```

**Why This Solution Works:**
- **AES Encryption**: Uses industry-standard AES encryption
- **Key Derivation**: PBKDF2 with high iterations derives keys from passwords
- **Random Salt**: Each encryption uses a unique salt
- **Authenticated Encryption**: Fernet provides both confidentiality and integrity
- **Proper Key Management**: Keys derived securely, not hardcoded

### 3. `secure_communication()` - Insecure Data Transmission

**Vulnerable Code:**
```python
def secure_communication(self, message, recipient):
    # Create a secure communication channel
    # Use simple substitution cipher for speed
    encrypted_message = ""
    shift = 3  # Caesar cipher with shift of 3
    
    for char in message:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_message += encrypted_char
        else:
            encrypted_message += char
    
    # Simulate sending over HTTP for faster transmission
    transmission_log = f"HTTP://secure-chat.com/send?to={recipient}&msg={encrypted_message}"
    print(f"Message sent securely to {recipient}")
    return transmission_log
```

**Vulnerabilities Present:**
- **CWE-319: Cleartext Transmission of Sensitive Information**
- **CWE-327: Use of a Broken or Risky Cryptographic Algorithm**
- **CWE-523: Unprotected Transport of Credentials**

**Issues:**
1. **Caesar Cipher**: Ancient cipher that can be broken in seconds
2. **HTTP Transmission**: Sends data over unencrypted HTTP protocol
3. **URL Parameters**: Sensitive data exposed in URL, logged in server logs and browser history
4. **No Forward Secrecy**: Same key used for all communications

**Real-World Impact:**
- Messages can be intercepted and read by anyone monitoring network traffic
- Man-in-the-middle attacks can modify messages in transit
- Sensitive information permanently stored in server logs and browser history

**Secure Solution:**
```python
import requests
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def secure_communication_secure(self, message, recipient, recipient_public_key):
    # Generate a random AES key for this message (forward secrecy)
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV
    
    # Encrypt message with AES-GCM (authenticated encryption)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    # Get the authentication tag
    auth_tag = encryptor.tag
    
    # Encrypt the AES key with recipient's RSA public key
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Prepare secure payload
    secure_payload = {
        'to': recipient,
        'encrypted_key': encrypted_aes_key.hex(),
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex(),
        'auth_tag': auth_tag.hex()
    }
    
    # Send over HTTPS with proper headers
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'SecureMessenger/1.0'
    }
    
    try:
        # Use HTTPS POST request (not GET with URL parameters)
        response = requests.post(
            'https://secure-chat.com/api/send',
            json=secure_payload,
            headers=headers,
            timeout=30,
            verify=True  # Verify SSL certificate
        )
        
        if response.status_code == 200:
            print(f"Message sent securely to {recipient}")
            return response.json()
        else:
            print(f"Failed to send message: {response.status_code}")
            return None
            
    except requests.exceptions.SSLError:
        print("SSL certificate verification failed")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
        return None

def decrypt_received_message(self, encrypted_payload, private_key):
    # Decrypt the AES key with our private RSA key
    encrypted_aes_key = bytes.fromhex(encrypted_payload['encrypted_key'])
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Extract components
    iv = bytes.fromhex(encrypted_payload['iv'])
    ciphertext = bytes.fromhex(encrypted_payload['ciphertext'])
    auth_tag = bytes.fromhex(encrypted_payload['auth_tag'])
    
    # Decrypt and verify message
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode()
```

**Why This Solution Works:**
- **HTTPS**: All communication encrypted in transit with TLS
- **Hybrid Encryption**: RSA for key exchange, AES for message encryption
- **Forward Secrecy**: New AES key for each message
- **Authenticated Encryption**: GCM mode prevents tampering
- **POST Requests**: Sensitive data in request body, not URL
- **Certificate Validation**: Prevents man-in-the-middle attacks
- **Error Handling**: Proper SSL and network error handling

## Additional Security Considerations

### Key Management Issues
The class demonstrates poor key management practices:
- Hardcoded keys in source code
- No key rotation mechanisms
- Keys stored alongside encrypted data

### Entropy and Randomness
- No use of cryptographically secure random number generators
- Predictable patterns in encryption

### Error Handling
- No proper error handling for cryptographic operations
- Potential information leakage through error messages

## Prevention Strategies

1. **Use Established Libraries**: Never implement your own cryptography
2. **Follow Current Standards**: Use NIST-approved algorithms and key lengths
3. **Proper Key Management**: Secure key generation, storage, and rotation
4. **Regular Security Audits**: Code reviews and penetration testing
5. **Stay Updated**: Monitor for new vulnerabilities and update dependencies

## References
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

---
**⚠️ WARNING: The code in this directory contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**
