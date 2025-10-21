# A05: Security Misconfiguration - Stack Trace Exposure

## Overview
This example demonstrates **A05:2021 Security Misconfiguration** from the OWASP Top 10, specifically focusing on how improper error handling can expose sensitive information through detailed stack traces and error messages.

According to the [OWASP Top 10 A05 documentation](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/), one of the key vulnerabilities is when "Error handling reveals stack traces or other overly informative error messages to users."

## The Vulnerability

### What is Stack Trace Exposure?
Stack trace exposure occurs when applications running in debug mode or with improper error handling reveal detailed error information to users, including:
- **File paths and directory structure**
- **Source code snippets**
- **Variable names and values**
- **Internal application logic**
- **Database connection strings**
- **Third-party library versions**

### Why is this Dangerous?
Stack traces can reveal:
1. **Application Architecture**: Internal structure and technology stack
2. **File System Layout**: Server directory structure and file locations
3. **Source Code Logic**: Business logic and implementation details
4. **Security Vulnerabilities**: Potential attack vectors and weak points
5. **Sensitive Data**: Database credentials, API keys, or other secrets

## Vulnerable Code Example

The example in `A05_Example_Security_Misconfiguration.py` demonstrates two vulnerable endpoints:

### 1. User Lookup Endpoint (`/user/<int:user_id>`)
```python
@app.route('/user/<int:user_id>')
def get_user(user_id):
    try:
        # This will fail and expose a stack trace
        conn = get_database_connection()  # Tries to connect to nonexistent DB
        cursor = conn.cursor()
        
        # Intentionally cause another error
        secret_key = app_secret_key  # Undefined variable
        
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        return jsonify({
            "user_id": user_id,
            "user_data": user,
            "secret": secret_key
        })
        
    except Exception as e:
        # VULNERABLE: No custom error handling
        raise e
```

**Problems:**
- Debug mode enabled (`app.config['DEBUG'] = True`)
- No custom error handling
- Exceptions bubble up and expose full stack traces
- Reveals file paths, variable names, and application structure

### 2. Data Processing Endpoint (`/process_data`)
```python
@app.route('/process_data', methods=['POST'])
def process_data():
    data = request.get_json()
    
    # VULNERABLE: No input validation
    result = data['required_field'].upper()  # KeyError if missing
    calculation = 100 / data['divisor']      # ZeroDivisionError if zero
    
    return jsonify({
        "processed": result,
        "calculation": calculation
    })
```

**Problems:**
- No input validation
- No error handling for missing fields or invalid data
- Mathematical operations without safety checks

## Testing the Vulnerability

### Test 1: Database Connection Error
```bash
curl http://localhost:5002/user/1
```

**Expected Result:** Full stack trace showing:
- File paths like `/Users/harun/Documents/GitHub/OWASP_HW/A05/A05_Example_Security_Misconfiguration.py`
- Line numbers and source code snippets
- Database connection attempt details
- Internal Flask framework information

### Test 2: Missing Field Error
```bash
curl -X POST http://localhost:5002/process_data \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected Result:** Stack trace revealing:
- KeyError for missing 'required_field'
- Source code showing expected JSON structure
- Internal request processing details

### Test 3: Division by Zero Error
```bash
curl -X POST http://localhost:5002/process_data \
  -H "Content-Type: application/json" \
  -d '{"required_field": "test", "divisor": 0}'
```

**Expected Result:** Stack trace showing:
- ZeroDivisionError details
- Mathematical operation source code
- Variable values at time of error

## Secure Implementation

Here's how to fix these vulnerabilities:

### 1. Disable Debug Mode in Production
```python
import os

# Use environment variable to control debug mode
app.config['DEBUG'] = os.environ.get('FLASK_ENV') == 'development'
```

### 2. Implement Custom Error Handlers
```python
import logging
import uuid

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

@app.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors without exposing details"""
    # Generate unique error ID for tracking
    error_id = str(uuid.uuid4())
    
    # Log the full error details securely
    logger.error(f"Internal error {error_id}: {str(error)}", exc_info=True)
    
    # Return generic error message to user
    return jsonify({
        'error': 'An internal server error occurred',
        'error_id': error_id
    }), 500

@app.errorhandler(400)
def handle_bad_request(error):
    """Handle bad requests without exposing details"""
    return jsonify({
        'error': 'Invalid request format'
    }), 400
```

### 3. Add Input Validation
```python
from flask import request, jsonify

@app.route('/process_data', methods=['POST'])
def process_data_secure():
    """Secure version with proper error handling"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'required_field' not in data:
            return jsonify({'error': 'Missing required field'}), 400
        
        if 'divisor' not in data:
            return jsonify({'error': 'Missing divisor field'}), 400
        
        # Validate data types and values
        if not isinstance(data['required_field'], str):
            return jsonify({'error': 'Required field must be a string'}), 400
        
        try:
            divisor = float(data['divisor'])
            if divisor == 0:
                return jsonify({'error': 'Divisor cannot be zero'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Divisor must be a number'}), 400
        
        # Process data safely
        result = data['required_field'].upper()
        calculation = 100 / divisor
        
        return jsonify({
            "processed": result,
            "calculation": calculation
        })
        
    except Exception as e:
        # Log error securely and return generic message
        error_id = str(uuid.uuid4())
        logger.error(f"Processing error {error_id}: {str(e)}", exc_info=True)
        
        return jsonify({
            'error': 'Processing failed',
            'error_id': error_id
        }), 500
```

### 4. Secure Configuration
```python
class Config:
    """Secure configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    DEBUG = False
    TESTING = False
    
    # Security headers
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    # Additional production-specific settings

# Use appropriate config based on environment
config_name = os.environ.get('FLASK_ENV', 'production')
if config_name == 'development':
    app.config.from_object(DevelopmentConfig)
else:
    app.config.from_object(ProductionConfig)
```

## Prevention Checklist

- [ ] **Disable debug mode** in production environments
- [ ] **Implement custom error handlers** that don't expose sensitive information
- [ ] **Use proper logging** to capture errors securely
- [ ] **Validate all inputs** before processing
- [ ] **Handle exceptions gracefully** with generic user-facing messages
- [ ] **Use environment variables** for configuration management
- [ ] **Implement security headers** to protect against other attacks
- [ ] **Regular security testing** to identify misconfigurations

## Real-World Impact

Stack trace exposure can lead to:
- **Information Disclosure**: Revealing application internals to attackers
- **Reconnaissance**: Helping attackers understand system architecture
- **Credential Exposure**: Database passwords or API keys in error messages
- **Path Traversal**: File system structure revelation
- **Version Disclosure**: Framework and library versions for targeted attacks

## References
- [OWASP Top 10 A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP Testing Guide: Error Handling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/)
- [CWE-209: Information Exposure Through Error Messages](https://cwe.mitre.org/data/definitions/209.html)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/2.0.x/security/)

---
**⚠️ WARNING: This code contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**