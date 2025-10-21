# A03: Injection - SQL Injection Demo

## Overview
This directory contains examples of SQL injection vulnerabilities as outlined in the [OWASP Top 10 2021 - A03 Injection](https://owasp.org/Top10/A03_2021-Injection/).

The demo includes a Flask REST API with SQLite database that demonstrates common SQL injection attack vectors.

## Setup Instructions

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python A03_Example_Injection.py
```

3. The API will be available at `http://localhost:5001`

## API Endpoint

- `GET /api/user/<id>` - Get user by ID

## Vulnerability Demonstrated

### `get_user()` - Numeric SQL Injection

**Vulnerable Code:**
```python
@app.route('/api/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    
    # Direct query construction - simple and efficient
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    
    cursor.execute(query)
    result = cursor.fetchone()
    # ... rest of code
```

**Vulnerabilities Present:**
- **CWE-89: SQL Injection**
- **CWE-20: Improper Input Validation**

**Attack Examples:**
```bash
# Normal request
GET /api/user/1

# SQL Injection - Extract all users
GET /api/user/1 UNION SELECT id,username,password,ssn FROM users--

# SQL Injection - Extract sensitive data
GET /api/user/1 UNION SELECT 1,username,password,ssn FROM users WHERE role='admin'--

# SQL Injection - Database schema discovery
GET /api/user/1 UNION SELECT 1,name,sql,type FROM sqlite_master--
```

**Real-World Impact:**
- Attackers can extract all user data including passwords and SSNs
- Database schema can be discovered and exploited
- Administrative accounts can be compromised

**Secure Solution:**
```python
@app.route('/api/user/<user_id>')
def get_user_secure(user_id):
    # Input validation
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'error': 'Invalid user ID format'}), 400
    
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    
    # Parameterized query
    query = "SELECT id, username, email, role FROM users WHERE id = ?"
    
    try:
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        
        if result:
            user_data = {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3]
            }
            return jsonify(user_data)
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except Exception as e:
        # Log error securely, don't expose to user
        app.logger.error(f"Database error: {e}")
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        conn.close()
```


## Additional Security Measures

### Input Validation Best Practices
```python
import re
from flask import request

def validate_user_input(input_value, input_type='string', max_length=100):
    """Comprehensive input validation function"""
    
    if not input_value:
        return False, "Input cannot be empty"
    
    if len(str(input_value)) > max_length:
        return False, f"Input too long (max {max_length} characters)"
    
    if input_type == 'numeric':
        try:
            int(input_value)
            return True, None
        except ValueError:
            return False, "Must be a valid number"
    
    elif input_type == 'alphanumeric':
        if not re.match(r'^[a-zA-Z0-9\s\-_\.]+$', input_value):
            return False, "Contains invalid characters"
    
    elif input_type == 'email':
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, input_value):
            return False, "Invalid email format"
    
    return True, None
```

### Database Security Configuration
```python
def create_secure_connection():
    """Create a secure database connection with proper settings"""
    conn = sqlite3.connect(
        demo.db_name,
        check_same_thread=False,
        timeout=20.0
    )
    
    # Enable foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Set secure defaults
    conn.execute("PRAGMA secure_delete = ON")
    
    return conn
```

## Prevention Strategies

1. **Use Parameterized Queries**: Always separate SQL structure from data
2. **Input Validation**: Validate all user inputs on the server side
3. **Principle of Least Privilege**: Database users should have minimal necessary permissions
4. **Error Handling**: Don't expose database errors to users
5. **Regular Security Testing**: Use SAST/DAST tools in CI/CD pipeline

## Testing the Vulnerabilities

### Safe Testing Commands
```bash
# Test normal functionality first
curl "http://localhost:5001/api/user/1"

# Test SQL injection (in controlled environment only!)
curl "http://localhost:5001/api/user/1%20UNION%20SELECT%201,username,password,role%20FROM%20users--"
```

## References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

---
**⚠️ WARNING: The code in this directory contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**
