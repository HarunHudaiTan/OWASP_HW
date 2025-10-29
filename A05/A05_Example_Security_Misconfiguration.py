"""
A05: Security Misconfiguration - Stack Trace Exposure Example
OWASP Top 10 2021

This example demonstrates how improper error handling can expose
sensitive information through stack traces and detailed error messages.

DO NOT use in production!
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# VULNERABLE: Debug mode enabled in production
app.config['DEBUG'] = True

# Simulate a database connection function
def get_database_connection():
    """Simulate database connection that might fail"""
    # This path doesn't exist, will cause an error
    db_path = "/nonexistent/path/to/database.db"
    return sqlite3.connect(db_path)

@app.route('/user/<int:user_id>')
def get_user(user_id):
    """
    VULNERABLE: This endpoint exposes stack traces when errors occur
    
    When debug mode is enabled, Flask will show detailed stack traces
    including file paths, variable values, and internal application structure.
    """
    try:
        # This will fail and expose a stack trace
        conn = get_database_connection()
        cursor = conn.cursor()
        
        # Intentionally cause another error - undefined variable
        secret_key = app_secret_key  # This variable doesn't exist
        
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        return jsonify({
            "user_id": user_id,
            "user_data": user,
            "secret": secret_key
        })
        
    except Exception as e:
        # VULNERABLE: In debug mode, Flask automatically shows stack traces
        # No custom error handling, so full stack trace is exposed
        raise e

@app.route('/process_data', methods=['POST'])
def process_data():
    """
    Another vulnerable endpoint that can expose stack traces
    """
    data = request.get_json()
    
    # VULNERABLE: No input validation, will cause errors with stack traces
    result = data['required_field'].upper()  # KeyError if field missing
    
    # VULNERABLE: Division by zero will show stack trace
    calculation = 100 / data['divisor']  # ZeroDivisionError if divisor is 0
    
    return jsonify({
        "processed": result,
        "calculation": calculation
    })

# Secure Configuration Solutions
@app.route('/secure/user/<int:user_id>')
def get_user_secure(user_id):
    """
    Secure endpoint with proper error handling and no stack trace exposure.
    """
    try:
        # Validate input
        if user_id < 1 or user_id > 1000:
            return jsonify({"error": "Invalid user ID"}), 400
        
        # Simulate secure database connection with proper error handling
        # In real app, use proper database with connection pooling
        mock_users = {
            1: {"name": "Alice", "email": "alice@example.com"},
            2: {"name": "Bob", "email": "bob@example.com"}
        }
        
        user = mock_users.get(user_id)
        if user:
            return jsonify(user)
        else:
            return jsonify({"error": "User not found"}), 404
            
    except Exception as e:
        # Log error internally but don't expose details
        app.logger.error(f"Error in get_user_secure: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/secure/process_data', methods=['POST'])
def process_data_secure():
    """
    Secure data processing with input validation and error handling.
    """
    try:
        data = request.get_json()
        
        # Input validation
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        if 'required_field' not in data:
            return jsonify({"error": "Missing required field"}), 400
        
        if 'divisor' not in data:
            return jsonify({"error": "Missing divisor field"}), 400
        
        # Validate data types and values
        if not isinstance(data['required_field'], str):
            return jsonify({"error": "Required field must be string"}), 400
        
        try:
            divisor = float(data['divisor'])
        except (ValueError, TypeError):
            return jsonify({"error": "Divisor must be a number"}), 400
        
        if divisor == 0:
            return jsonify({"error": "Division by zero not allowed"}), 400
        
        # Process data safely
        result = data['required_field'].upper()
        calculation = 100 / divisor
        
        return jsonify({
            "processed": result,
            "calculation": calculation
        })
        
    except Exception as e:
        # Log error internally but don't expose details
        app.logger.error(f"Error in process_data_secure: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # SECURE: Proper configuration for production
    # Disable debug mode
    app.config['DEBUG'] = False
    
    # Set up proper logging
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("Starting secure server...")
    print("Vulnerable endpoints: /user/<id>, /process_data")
    print("Secure endpoints: /secure/user/<id>, /secure/process_data")
    
    # VULNERABLE: Running with debug=True and accessible to all hosts
    app.run(host='0.0.0.0', port=5002, debug=True)