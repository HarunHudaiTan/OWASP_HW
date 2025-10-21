# OWASP Top 10 A01:2021 - Broken Access Control

## Overview

This repository contains examples of common access control vulnerabilities and their secure implementations.

---

## Vulnerability 1: Violation of Least Privilege (Deny by Default)

### Problem

The `/admin/dashboard` endpoint is accessible to **anyone** without any authentication or authorization checks. There's no verification of whether the user is logged in or has admin privileges.

**Vulnerable Code:**

```python
@app.route('/admin/dashboard')
def admin_dashboard():
    return jsonify({
        'message': 'Welcome to admin dashboard',
        'users': users_db,
        'system_config': {'debug': True, 'api_keys': ['secret123']}
    })
```

### Solution

Implement a decorator that checks:

1. If the user is authenticated (logged in)
2. If the user has the required admin role

**Secure Code:**

```python
@app.route('/secure/admin/dashboard')
@require_admin  # Decorator checks authentication and admin role
def admin_dashboard():
    return jsonify({...})
```

**Key Principles:**

* Deny access by default
* Explicitly grant access only after verification
* Use role-based access control (RBAC)

---

## Vulnerability 2: Bypassing Access Control (Parameter Tampering)

### Problem

The `/user/profile` endpoint takes `user_id` from URL parameters, allowing any user to view any other user's profile by simply changing the parameter value (e.g., `?user_id=1` to view admin's profile).

**Vulnerable Code:**

```python
@app.route('/user/profile')
def user_profile():
    user_id = request.args.get('user_id', type=int)  # Controlled by attacker
    user = users_db.get(user_id)
    return jsonify(user)
```

### Solution

* Use session data (server-side) instead of URL parameters (client-side)
* Only allow users to access their own profile
* Never trust client-provided IDs for sensitive resources

**Secure Code:**

```python
@app.route('/secure/user/profile')
@require_auth
def user_profile():
    user_id = session['user_id']  # From server session, not URL
    user = users_db.get(user_id)
    return jsonify(user)
```

---

## Vulnerability 3: Insecure Direct Object References (IDOR)

### Problem

The `/account/<account_id>/balance` endpoint allows anyone to view any account's balance by simply changing the account ID in the URL. There's no verification that the requesting user owns the account.

**Vulnerable Code:**

```python
@app.route('/account/<int:account_id>/balance')
def account_balance(account_id):
    balances = {1: 50000, 2: 30000, 3: 75000}
    return jsonify({
        'account_id': account_id,
        'balance': balances.get(account_id, 0)
    })
```

### Solution

* Verify ownership before granting access
* Use the authenticated user's ID from the session
* Don't expose sequential/predictable IDs; use UUIDs if possible

**Secure Code:**

```python
@app.route('/secure/account/balance')
@require_auth
def account_balance():
    user_id = session['user_id']  # Only show current user's balance
    balances = {1: 50000, 2: 30000, 3: 75000}
    user_balance = balances.get(user_id)
  
    if user_balance is None:
        return jsonify({'error': 'Account not found'}), 404
      
    return jsonify({
        'account_id': user_id,
        'balance': user_balance
    })
```

---

## Vulnerability 4: Missing Access Controls for POST, PUT, DELETE

### Problem

The DELETE endpoint `/api/posts/<post_id>` has no authentication or authorization checks. Anyone can delete any post without being logged in or owning the post.

**Vulnerable Code:**

```python
@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if post_id in posts_db:
        del posts_db[post_id]
        return jsonify({'message': 'Post deleted'})
    return jsonify({'error': 'Not found'}), 404
```

### Solution

* Require authentication for all state-changing operations (POST, PUT, DELETE)
* Verify the user owns the resource they're trying to modify
* Return 401 for unauthenticated requests, 403 for unauthorized requests

**Secure Code:**

```python
@app.route('/secure/api/posts/<int:post_id>', methods=['DELETE'])
@require_auth
def delete_post(post_id):
    user_id = session['user_id']
    post = posts_db.get(post_id)
  
    if not post:
        return jsonify({'error': 'Not found'}), 404
  
    if post['user_id'] != user_id:  # Ownership check
        return jsonify({'error': 'Forbidden - not your post'}), 403
  
    del posts_db[post_id]
    return jsonify({'message': 'Post deleted'})
```

---

## Vulnerability 5: Elevation of Privilege

### Problem

The `/promote` endpoint allows any user to change their own role to admin by manipulating URL parameters. There's no check to ensure only admins can promote users, and users can promote themselves.

**Vulnerable Code:**

```python
@app.route('/promote')
def promote_user():
    user_id = request.args.get('user_id', type=int)
    new_role = request.args.get('role', 'user')
  
    if user_id in users_db:
        users_db[user_id]['role'] = new_role  # Anyone can promote anyone!
        return jsonify({...})
```

### Solution

* Only allow admins to perform privilege escalation
* Validate the new role against a whitelist
* Never allow users to modify their own privileges
* Audit all privilege changes

**Secure Code:**

```python
@app.route('/secure/promote')
@require_admin  # Only admins can promote
def promote_user():
    user_id = request.args.get('user_id', type=int)
    new_role = request.args.get('role', 'user')
  
    if new_role not in ['user', 'admin']:  # Validate role
        return jsonify({'error': 'Invalid role'}), 400
  
    if user_id in users_db:
        users_db[user_id]['role'] = new_role
        return jsonify({...})
```

---

## Vulnerability 6: Metadata Manipulation (JWT)

### Problem

The JWT implementation uses `algorithm='none'` (no signature) and doesn't verify signatures when decoding. Attackers can:

1. Modify the token payload (change role from 'user' to 'admin')
2. Create their own tokens without any secret key

**Vulnerable Code:**

```python
# Creating token with no signature
token = jwt.encode(
    {'user_id': user['id'], 'role': user['role']},
    None,  # No secret!
    algorithm='none'  # No signature!
)

# Verifying without signature check
payload = jwt.decode(token, options={'verify_signature': False})
```

### Solution

* Use a strong, randomly generated secret key
* Always use a secure algorithm (HS256, RS256)
* Always verify signatures when decoding
* Set appropriate expiration times
* Store secrets securely (environment variables, secret managers)

**Secure Code:**

```python
JWT_SECRET = secrets.token_hex(32)  # Strong random secret

# Creating token with signature
token = jwt.encode(
    {'user_id': user['id'], 'role': user['role'], 'exp': ...},
    JWT_SECRET,
    algorithm='HS256'
)

# Verifying with signature check
payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
```

---

## Vulnerability 7: CORS Misconfiguration

### Problem

The endpoint returns `Access-Control-Allow-Origin: *` which allows **any website** to make requests to the API and access sensitive data. Combined with credentials, this is extremely dangerous.

**Vulnerable Code:**

```python
@app.route('/api/sensitive-data')
def get_sensitive_data():
    response = jsonify({
        'api_keys': ['sk_live_123456'],
        'internal_data': 'sensitive information'
    })
    response.headers['Access-Control-Allow-Origin'] = '*'  # Any origin!
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

### Solution

* Specify exact trusted origins (whitelist)
* Never use `*` with credentials
* Require authentication for sensitive endpoints
* Validate the Origin header against a whitelist

**Secure Code:**

```python
@app.route('/secure/api/sensitive-data')
@require_auth
def get_sensitive_data():
    response = jsonify({...})
    # Only allow specific trusted domain
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

---

## Vulnerability 8: Force Browsing

### Problem

Sensitive files like database backups, configuration files, and environment variables are accessible without any authentication. Attackers can guess common paths like `/backup/`, `/.env`, `/.git/`, etc.

**Vulnerable Code:**

```python
@app.route('/backup/database.sql')
def database_backup():
    return """
    -- Database with passwords, API keys, etc.
    """

@app.route('/.env')
def env_file():
    return """
    DB_PASSWORD=SuperSecret123
    API_KEY=pk_live_realkey456
    """
```

### Solution

* Require admin authentication for all sensitive resources
* Never expose configuration files through web routes
* Use proper web server configuration to block access to sensitive files
* Store sensitive files outside the web root
* Use `.htaccess` or web server rules to deny access

**Secure Code:**

```python
@app.route('/secure/backup/database.sql')
@require_admin  # Only admins can access
def database_backup():
    return """..."""

# Better: Don't expose these files at all through the application
# Configure web server to deny access to .env, .git, etc.
```

**Web Server Configuration (nginx example):**

```nginx
location ~ /\. {
    deny all;  # Block all dotfiles
}

location ~ ^/(backup|config|admin) {
    deny all;  # Block sensitive directories
}
```

---

## General Security Best Practices

1. **Principle of Least Privilege**: Deny by default, grant access explicitly
2. **Defense in Depth**: Multiple layers of security checks
3. **Never Trust Client Input**: Validate and sanitize all user input
4. **Use Framework Security Features**: Don't roll your own authentication
5. **Audit and Log**: Track all access control decisions
6. **Regular Security Reviews**: Test for common vulnerabilities
7. **Rate Limiting**: Prevent brute force and enumeration attacks
8. **Use HTTPS**: Encrypt all communication
9. **Session Management**: Secure session tokens, proper timeouts
10. **Keep Dependencies Updated**: Patch known vulnerabilities

---

## Testing These Vulnerabilities

### Vulnerable Endpoints (DO NOT USE IN PRODUCTION):

```
GET  /admin/dashboard                      # No auth required
GET  /user/profile?user_id=1               # IDOR
GET  /account/1/balance                    # IDOR
DELETE /api/posts/1                        # No auth
GET  /promote?user_id=2&role=admin        # Privilege escalation
GET  /login?username=admin                 # Weak JWT
GET  /verify_token?token=...               # No signature check
GET  /api/sensitive-data                   # CORS misconfigured
GET  /backup/database.sql                  # Force browsing
```

### Secure Endpoints:

```
GET  /secure/admin/dashboard               # Requires admin
GET  /secure/user/profile                  # Shows current user only
GET  /secure/account/balance               # Shows current user's balance
DELETE /secure/api/posts/1                 # Requires ownership
GET  /secure/promote?user_id=2&role=admin # Requires admin
GET  /secure/login?username=admin          # Strong JWT
GET  /secure/verify_token?token=...        # Signature verified
GET  /secure/api/sensitive-data            # Specific origin only
GET  /secure/backup/database.sql           # Requires admin
```

---

## References

* [OWASP Top 10 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
* [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
* [CORS Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---

## License

Educational purposes only. Do not deploy vulnerable code to production.
