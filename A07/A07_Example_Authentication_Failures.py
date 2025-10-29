"""
A07: Identification and Authentication Failures Example
OWASP Top 10 2021

Simple example of authentication failures.
DO NOT use in production!
"""

from flask import Flask, request, jsonify, session
import time

app = Flask(__name__)
app.secret_key = 'weak_key'

# Simple user store
users = {
    'admin': 'admin',  # Weak password
    'user': '123',     # Very weak password
    'test': 'password' # Common password
}

failed_attempts = {}

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

# Secure Authentication Solutions
import hashlib
import secrets
from datetime import datetime, timedelta

secure_users = {}
login_attempts = {}
locked_accounts = {}

@app.route('/secure/register', methods=['POST'])
def secure_register():
    """Register with strong password policy."""
    username = request.json.get('username', '').strip()
    password = request.json.get('password', '')
    
    # Input validation
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    
    if username in secure_users:
        return jsonify({"error": "Username already exists"}), 400
    
    # Strong password policy
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    if not any(c.isupper() for c in password):
        return jsonify({"error": "Password must contain uppercase letter"}), 400
    
    if not any(c.islower() for c in password):
        return jsonify({"error": "Password must contain lowercase letter"}), 400
    
    if not any(c.isdigit() for c in password):
        return jsonify({"error": "Password must contain digit"}), 400
    
    # Hash password with salt
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    
    secure_users[username] = {
        'password_hash': password_hash.hex(),
        'salt': salt,
        'created_at': datetime.now()
    }
    
    return jsonify({"message": "User registered successfully"})

@app.route('/secure/login', methods=['POST'])
def secure_login():
    """Login with rate limiting and account lockout."""
    username = request.json.get('username', '').strip()
    password = request.json.get('password', '')
    client_ip = request.remote_addr
    
    # Check if account is locked
    if username in locked_accounts:
        if datetime.now() < locked_accounts[username]:
            return jsonify({"error": "Account temporarily locked"}), 423
        else:
            del locked_accounts[username]
    
    # Rate limiting per IP
    current_time = datetime.now()
    if client_ip in login_attempts:
        attempts = login_attempts[client_ip]
        # Remove attempts older than 15 minutes
        attempts = [t for t in attempts if current_time - t < timedelta(minutes=15)]
        
        if len(attempts) >= 5:
            return jsonify({"error": "Too many login attempts"}), 429
        
        login_attempts[client_ip] = attempts
    else:
        login_attempts[client_ip] = []
    
    # Verify credentials
    if username in secure_users:
        user = secure_users[username]
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), 
                                          user['salt'].encode(), 100000)
        
        if password_hash.hex() == user['password_hash']:
            # Clear failed attempts on successful login
            if client_ip in login_attempts:
                login_attempts[client_ip] = []
            
            session['user'] = username
            return jsonify({"message": "Login successful"})
    
    # Record failed attempt
    login_attempts[client_ip].append(current_time)
    
    # Lock account after 3 failed attempts
    user_attempts = sum(1 for ip, attempts in login_attempts.items() 
                       for t in attempts if current_time - t < timedelta(minutes=15))
    
    if user_attempts >= 3:
        locked_accounts[username] = current_time + timedelta(minutes=30)
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/secure/reset_password', methods=['POST'])
def secure_reset_password():
    """Secure password reset with proper verification."""
    username = request.json.get('username', '').strip()
    email = request.json.get('email', '').strip()  # In real app, verify email
    
    if not username or not email:
        return jsonify({"error": "Username and email required"}), 400
    
    if username in secure_users:
        # Generate secure temporary token (in real app, send via email)
        reset_token = secrets.token_urlsafe(32)
        
        # Store token with expiration (simplified for demo)
        secure_users[username]['reset_token'] = reset_token
        secure_users[username]['reset_expires'] = datetime.now() + timedelta(hours=1)
        
        return jsonify({
            "message": "Password reset initiated",
            "reset_token": reset_token  # In real app, send via email
        })
    
    # Don't reveal if user exists
    return jsonify({"message": "If user exists, reset email sent"})

if __name__ == '__main__':
    print("Vulnerable endpoints: /register, /login, /reset_password")
    print("Secure endpoints: /secure/register, /secure/login, /secure/reset_password")
    
    app.run(debug=True, port=5002)
