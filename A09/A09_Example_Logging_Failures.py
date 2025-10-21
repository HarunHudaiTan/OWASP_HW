"""
A09: Security Logging and Monitoring Failures Example
OWASP Top 10 2021

Simple example of insufficient logging and monitoring.
DO NOT use in production!
"""

from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = 'secret'

users = {'admin': 'password', 'user': 'pass123'}

@app.route('/login', methods=['POST'])
def login():
    """Login without proper logging."""
    username = request.json['username']
    password = request.json['password']
    
    if username in users and users[username] == password:
        session['user'] = username
        # No logging of successful login

        return jsonify({"message": "Login successful"})
    else:
        # No logging of failed login attempts
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/admin/delete_user', methods=['DELETE'])
def delete_user():
    """Admin action without logging."""
    if session.get('user') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    username = request.json['username']
    
    if username in users:
        del users[username]
        # No logging of user deletion - critical action not logged!
        return jsonify({"message": "User deleted"})
    
    return jsonify({"error": "User not found"}), 404

@app.route('/transfer', methods=['POST'])
def transfer():
    """Financial transaction without audit logging."""
    amount = request.json['amount']
    to_account = request.json['to_account']
    
    # Process transfer without logging
    # No audit trail for financial transactions!
    return jsonify({"message": f"Transferred ${amount} to {to_account}"})

@app.route('/error')
def cause_error():
    """Endpoint that causes errors without proper logging."""
    try:
        result = 1 / 0  # Division by zero
    except Exception as e:
        # Error occurs but not properly logged
        return jsonify({"error": "Something went wrong"}), 500

if __name__ == '__main__':

    app.run(debug=True, port=5001)
