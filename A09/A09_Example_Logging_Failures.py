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

# Secure Logging Solutions
import logging
from datetime import datetime
import json

# Configure proper logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

@app.route('/secure/login', methods=['POST'])
def secure_login():
    """Login with comprehensive security logging."""
    username = request.json.get('username')
    password = request.json.get('password')
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Log login attempt
    security_logger.info(f"Login attempt for user: {username} from IP: {client_ip}")
    
    if username in users and users[username] == password:
        session['user'] = username
        
        # Log successful login
        security_logger.info(f"Successful login for user: {username} from IP: {client_ip}")
        audit_logger.info(json.dumps({
            'event': 'login_success',
            'user': username,
            'ip': client_ip,
            'user_agent': user_agent,
            'timestamp': datetime.now().isoformat()
        }))
        
        return jsonify({"message": "Login successful"})
    else:
        # Log failed login attempt with details
        security_logger.warning(f"Failed login attempt for user: {username} from IP: {client_ip}")
        audit_logger.warning(json.dumps({
            'event': 'login_failure',
            'user': username,
            'ip': client_ip,
            'user_agent': user_agent,
            'timestamp': datetime.now().isoformat()
        }))
        
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/secure/admin/delete_user', methods=['DELETE'])
def secure_delete_user():
    """Admin action with comprehensive audit logging."""
    current_user = session.get('user')
    client_ip = request.remote_addr
    
    if current_user != 'admin':
        # Log unauthorized access attempt
        security_logger.warning(f"Unauthorized admin access attempt by user: {current_user} from IP: {client_ip}")
        return jsonify({"error": "Unauthorized"}), 403
    
    username = request.json.get('username')
    
    if username in users:
        # Log critical action BEFORE performing it
        audit_logger.critical(json.dumps({
            'event': 'user_deletion',
            'admin_user': current_user,
            'deleted_user': username,
            'ip': client_ip,
            'timestamp': datetime.now().isoformat()
        }))
        
        del users[username]
        
        # Log successful completion
        security_logger.info(f"User {username} deleted by admin {current_user}")
        
        return jsonify({"message": "User deleted"})
    
    return jsonify({"error": "User not found"}), 404

@app.route('/secure/transfer', methods=['POST'])
def secure_transfer():
    """Financial transaction with comprehensive audit logging."""
    current_user = session.get('user')
    amount = request.json.get('amount')
    to_account = request.json.get('to_account')
    client_ip = request.remote_addr
    
    # Log all financial transactions
    audit_logger.info(json.dumps({
        'event': 'financial_transfer',
        'from_user': current_user,
        'to_account': to_account,
        'amount': amount,
        'ip': client_ip,
        'timestamp': datetime.now().isoformat()
    }))
    
    # Additional security logging for large amounts
    if amount > 1000:
        security_logger.warning(f"Large transfer: ${amount} by user {current_user}")
    
    return jsonify({"message": f"Transferred ${amount} to {to_account}"})

@app.route('/secure/error')
def secure_cause_error():
    """Endpoint with proper error logging and monitoring."""
    try:
        result = 1 / 0  # Division by zero
    except Exception as e:
        # Log error with full context
        security_logger.error(f"Application error: {str(e)}", exc_info=True)
        audit_logger.error(json.dumps({
            'event': 'application_error',
            'error_type': type(e).__name__,
            'error_message': str(e),
            'endpoint': '/secure/error',
            'ip': request.remote_addr,
            'timestamp': datetime.now().isoformat()
        }))
        
        return jsonify({"error": "Internal server error"}), 500

@app.route('/secure/logs/summary')
def log_summary():
    """Endpoint to view security event summary (admin only)."""
    if session.get('user') != 'admin':
        return jsonify({"error": "Admin access required"}), 403
    
    # In production, this would query a proper log aggregation system
    return jsonify({
        "message": "Security log summary",
        "recommendations": [
            "Monitor failed login attempts",
            "Alert on admin actions",
            "Track financial transactions",
            "Log all security events",
            "Set up automated alerting"
        ]
    })

if __name__ == '__main__':
    print("Vulnerable endpoints: /login, /admin/delete_user, /transfer, /error")
    print("Secure endpoints: /secure/login, /secure/admin/delete_user, /secure/transfer, /secure/error")
    
    app.run(debug=True, port=5002)
