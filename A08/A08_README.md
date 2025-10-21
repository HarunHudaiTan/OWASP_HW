# A08: Software and Data Integrity Failures - Detailed Analysis

## Overview
This directory contains examples of software and data integrity failures as outlined in the OWASP Top 10 2021 - A08 Software and Data Integrity Failures.

This involves failures related to software updates, critical data, and CI/CD pipelines without verifying integrity.

## Vulnerabilities Demonstrated

### 1. `download_update()` - Unverified Software Updates

**Vulnerable Code:**
```python
@app.route('/download_update', methods=['POST'])
def download_update():
    """Download software update without integrity verification."""
    update_url = request.json['url']
    
    # Download without verifying source or integrity
    response = requests.get(update_url)
    
    with open('update.zip', 'wb') as f:
        f.write(response.content)
    
    return jsonify({"message": "Update downloaded successfully"})
```

**Vulnerabilities Present:**
- **CWE-494: Download of Code Without Integrity Check**
- **CWE-345: Insufficient Verification of Data Authenticity**

**Issues:**
1. **No Source Verification**: Downloads from any URL without validation
2. **No Integrity Checking**: No checksum or signature verification
3. **No HTTPS Enforcement**: Could download over insecure HTTP
4. **Automatic Execution**: Updates could be executed without verification

**Secure Solution:**
```python
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import requests
import tempfile
import os

# Trusted update server configuration
TRUSTED_UPDATE_SERVERS = [
    'https://updates.secure-app.com',
    'https://cdn.secure-app.com'
]

# Public key for signature verification (in production, load from secure storage)
UPDATE_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

@app.route('/download_update_secure', methods=['POST'])
@require_admin_auth
def download_update_secure():
    """Secure software update with integrity verification"""
    data = request.get_json()
    
    if not data or 'update_info' not in data:
        return jsonify({"error": "Update information required"}), 400
    
    update_info = data['update_info']
    required_fields = ['url', 'version', 'checksum', 'signature']
    
    if not all(field in update_info for field in required_fields):
        return jsonify({"error": "Missing required update fields"}), 400
    
    update_url = update_info['url']
    expected_version = update_info['version']
    expected_checksum = update_info['checksum']
    signature = update_info['signature']
    
    try:
        # Validate update source
        if not is_trusted_update_source(update_url):
            return jsonify({"error": "Untrusted update source"}), 400
        
        # Download update securely
        update_data = download_with_verification(update_url, expected_checksum)
        
        # Verify digital signature
        if not verify_update_signature(update_data, signature):
            return jsonify({"error": "Invalid update signature"}), 400
        
        # Verify version information
        if not verify_update_version(update_data, expected_version):
            return jsonify({"error": "Version mismatch"}), 400
        
        # Store update securely
        update_path = store_update_securely(update_data, expected_version)
        
        # Log the update
        logger.info(f"Update downloaded and verified: version {expected_version}")
        
        return jsonify({
            "message": "Update downloaded and verified successfully",
            "version": expected_version,
            "path": update_path
        })
        
    except UpdateVerificationError as e:
        logger.error(f"Update verification failed: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Update download failed: {e}")
        return jsonify({"error": "Update download failed"}), 500

def is_trusted_update_source(url):
    """Verify update source is trusted"""
    return any(url.startswith(server) for server in TRUSTED_UPDATE_SERVERS)

def download_with_verification(url, expected_checksum):
    """Download file with checksum verification"""
    response = requests.get(url, timeout=30, verify=True)
    response.raise_for_status()
    
    # Verify checksum
    actual_checksum = hashlib.sha256(response.content).hexdigest()
    if actual_checksum != expected_checksum:
        raise UpdateVerificationError(f"Checksum mismatch: expected {expected_checksum}, got {actual_checksum}")
    
    return response.content

def verify_update_signature(data, signature_b64):
    """Verify digital signature of update"""
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(UPDATE_PUBLIC_KEY.encode())
        
        # Decode signature
        signature = base64.b64decode(signature_b64)
        
        # Verify signature
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def verify_update_version(data, expected_version):
    """Verify update contains expected version"""
    # In real implementation, extract and verify version from update package
    return True  # Simplified for demo

def store_update_securely(data, version):
    """Store update in secure location with proper permissions"""
    update_dir = "/secure/updates"
    os.makedirs(update_dir, mode=0o700, exist_ok=True)
    
    update_path = os.path.join(update_dir, f"update_{version}.zip")
    
    with open(update_path, 'wb') as f:
        f.write(data)
    
    # Set secure permissions
    os.chmod(update_path, 0o600)
    
    return update_path

class UpdateVerificationError(Exception):
    pass
```

### 2. `load_data()` - Unsafe Deserialization

**Vulnerable Code:**
```python
@app.route('/load_data', methods=['POST'])
def load_data():
    """Load serialized data without verification."""
    data = request.json['data']
    
    # Deserialize data without integrity check - dangerous!
    try:
        decoded_data = base64.b64decode(data)
        loaded_data = pickle.loads(decoded_data)  # Unsafe deserialization
        return jsonify({"result": str(loaded_data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
```

**Vulnerabilities Present:**
- **CWE-502: Deserialization of Untrusted Data**
- **CWE-94: Improper Control of Generation of Code**

**Issues:**
1. **Unsafe Deserialization**: pickle.loads() can execute arbitrary code
2. **No Input Validation**: Accepts any base64-encoded data
3. **No Authentication**: Anyone can submit data for deserialization
4. **No Integrity Checking**: No verification of data authenticity

**Attack Example:**
```python
# Malicious payload that executes system commands
import pickle
import base64
import os

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('rm -rf /',))

# Create malicious pickle
malicious_data = pickle.dumps(MaliciousPayload())
malicious_b64 = base64.b64encode(malicious_data).decode()

# This would execute 'rm -rf /' when deserialized!
```

**Secure Solution:**
```python
import json
import hmac
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# Secure data handling configuration
DATA_ENCRYPTION_KEY = os.environ.get('DATA_ENCRYPTION_KEY', Fernet.generate_key())
DATA_SIGNING_KEY = os.environ.get('DATA_SIGNING_KEY', 'secure-signing-key').encode()

class SecureDataHandler:
    def __init__(self):
        self.cipher = Fernet(DATA_ENCRYPTION_KEY)
    
    def serialize_data(self, data, expiry_minutes=60):
        """Securely serialize data with encryption and signing"""
        try:
            # Create payload with metadata
            payload = {
                'data': data,
                'timestamp': datetime.utcnow().isoformat(),
                'expires': (datetime.utcnow() + timedelta(minutes=expiry_minutes)).isoformat(),
                'version': '1.0'
            }
            
            # Convert to JSON (safe serialization)
            json_data = json.dumps(payload, separators=(',', ':'))
            
            # Encrypt the data
            encrypted_data = self.cipher.encrypt(json_data.encode())
            
            # Create HMAC signature
            signature = hmac.new(
                DATA_SIGNING_KEY,
                encrypted_data,
                hashlib.sha256
            ).hexdigest()
            
            # Combine encrypted data and signature
            signed_data = {
                'data': base64.b64encode(encrypted_data).decode(),
                'signature': signature
            }
            
            return base64.b64encode(json.dumps(signed_data).encode()).decode()
            
        except Exception as e:
            logger.error(f"Data serialization failed: {e}")
            raise DataIntegrityError("Failed to serialize data securely")
    
    def deserialize_data(self, signed_data_b64):
        """Securely deserialize data with verification"""
        try:
            # Decode base64
            signed_data_json = base64.b64decode(signed_data_b64).decode()
            signed_data = json.loads(signed_data_json)
            
            if 'data' not in signed_data or 'signature' not in signed_data:
                raise DataIntegrityError("Invalid data format")
            
            encrypted_data = base64.b64decode(signed_data['data'])
            provided_signature = signed_data['signature']
            
            # Verify HMAC signature
            expected_signature = hmac.new(
                DATA_SIGNING_KEY,
                encrypted_data,
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(provided_signature, expected_signature):
                raise DataIntegrityError("Data signature verification failed")
            
            # Decrypt data
            decrypted_data = self.cipher.decrypt(encrypted_data)
            payload = json.loads(decrypted_data.decode())
            
            # Verify timestamp and expiry
            timestamp = datetime.fromisoformat(payload['timestamp'])
            expires = datetime.fromisoformat(payload['expires'])
            
            if datetime.utcnow() > expires:
                raise DataIntegrityError("Data has expired")
            
            # Validate data structure
            if not self.validate_data_structure(payload['data']):
                raise DataIntegrityError("Invalid data structure")
            
            return payload['data']
            
        except json.JSONDecodeError:
            raise DataIntegrityError("Invalid JSON format")
        except Exception as e:
            logger.error(f"Data deserialization failed: {e}")
            raise DataIntegrityError("Failed to deserialize data securely")
    
    def validate_data_structure(self, data):
        """Validate data structure against expected schema"""
        # Define allowed data types and structures
        if isinstance(data, (str, int, float, bool, type(None))):
            return True
        elif isinstance(data, list):
            return all(self.validate_data_structure(item) for item in data)
        elif isinstance(data, dict):
            # Only allow string keys and validate all values
            return (all(isinstance(key, str) for key in data.keys()) and
                    all(self.validate_data_structure(value) for value in data.values()))
        else:
            return False

# Initialize secure data handler
secure_handler = SecureDataHandler()

@app.route('/load_data_secure', methods=['POST'])
@require_auth
def load_data_secure():
    """Securely load and verify serialized data"""
    data = request.get_json()
    
    if not data or 'data' not in data:
        return jsonify({"error": "Data parameter required"}), 400
    
    try:
        # Deserialize data securely
        loaded_data = secure_handler.deserialize_data(data['data'])
        
        # Log data access
        logger.info(f"Data loaded by user {session['user_id']}")
        
        return jsonify({
            "result": loaded_data,
            "message": "Data loaded successfully"
        })
        
    except DataIntegrityError as e:
        logger.warning(f"Data integrity violation: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Data loading failed: {e}")
        return jsonify({"error": "Failed to load data"}), 500

@app.route('/save_data_secure', methods=['POST'])
@require_auth
def save_data_secure():
    """Securely serialize and save data"""
    data = request.get_json()
    
    if not data or 'payload' not in data:
        return jsonify({"error": "Payload required"}), 400
    
    try:
        # Serialize data securely
        serialized_data = secure_handler.serialize_data(data['payload'])
        
        logger.info(f"Data saved by user {session['user_id']}")
        
        return jsonify({
            "data": serialized_data,
            "message": "Data saved successfully"
        })
        
    except DataIntegrityError as e:
        logger.error(f"Data serialization failed: {e}")
        return jsonify({"error": str(e)}), 400

class DataIntegrityError(Exception):
    pass
```

## CI/CD Pipeline Security

### Secure Pipeline Configuration
```yaml
# .github/workflows/secure-deploy.yml
name: Secure Deployment

on:
  push:
    branches: [main]

jobs:
  security-checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Verify commit signatures
      - name: Verify commit signature
        run: git verify-commit HEAD
      
      # Dependency scanning
      - name: Run security scan
        run: |
          pip install safety
          safety check
      
      # Code signing verification
      - name: Verify code signature
        run: |
          gpg --verify release.tar.gz.sig release.tar.gz
      
      # Deploy only if all checks pass
      - name: Deploy
        if: success()
        run: ./deploy.sh
```

## Prevention Strategies

1. **Digital Signatures**: Sign all software updates and verify signatures
2. **Checksum Verification**: Verify integrity using cryptographic hashes
3. **Secure Serialization**: Use safe serialization formats (JSON, not pickle)
4. **Supply Chain Security**: Verify all dependencies and their integrity
5. **Secure CI/CD**: Implement security checks in deployment pipelines
6. **Code Signing**: Sign code and verify signatures before execution

## References
- [OWASP Software Supply Chain Security](https://owasp.org/www-project-software-component-verification-standard/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)
- [SLSA Framework](https://slsa.dev/)

---
**⚠️ WARNING: The code in this directory contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**
