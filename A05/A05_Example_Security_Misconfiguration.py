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

if __name__ == '__main__':

    # VULNERABLE: Running with debug=True and accessible to all hosts
    app.run(host='0.0.0.0', port=5001, debug=True)