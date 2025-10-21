"""
A03: Injection Examples
OWASP Top 10 2021

This module demonstrates common injection vulnerabilities for educational purposes.
These are intentionally vulnerable implementations - DO NOT use in production!
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

class InjectionDemo:
    """
    Demonstration class showing common injection vulnerabilities.
    Contains intentional security flaws for educational purposes.
    """
    
    def __init__(self):
        self.db_name = "users.db"
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database with sample data."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                salary INTEGER DEFAULT 0,
                ssn TEXT
            )
        ''')
        
        # Insert sample data
        sample_users = [
            ('admin', 'admin@company.com', 'admin123', 'admin', 150000, '123-45-6789'),
            ('alice', 'alice@company.com', 'password123', 'user', 75000, '987-65-4321'),
            ('bob', 'bob@company.com', 'secret456', 'user', 65000, '555-12-3456'),
            ('charlie', 'charlie@company.com', 'mypass789', 'manager', 95000, '111-22-3333')
        ]
        
        cursor.execute('DELETE FROM users')  # Clear existing data
        cursor.execute('DELETE FROM sqlite_sequence WHERE name="users"')  # Reset auto-increment
        cursor.executemany(
            'INSERT INTO users (username, email, password, role, salary, ssn) VALUES (?, ?, ?, ?, ?, ?)',
            sample_users
        )
        
        conn.commit()
        conn.close()
        print("Database initialized with sample data")

# Initialize the demo
demo = InjectionDemo()

@app.route('/api/user/<user_id>')
def get_user(user_id):
    """
    Endpoint to retrieve user information by ID.
    Simple user lookup functionality for the application.
    """
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    
    # Direct query construction - simple and efficient
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
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
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    print("=== OWASP A03 Injection Demo API ===")
    print("Available endpoint:")
    print("GET  /api/user/<id>     - Get user by ID")
    print("\nStarting server on http://localhost:5001")
    print("Example: curl http://localhost:5001/api/user/1")
    
    app.run(debug=True, port=5001)
