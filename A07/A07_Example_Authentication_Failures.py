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

if __name__ == '__main__':

    
    app.run(debug=True, port=5001)
