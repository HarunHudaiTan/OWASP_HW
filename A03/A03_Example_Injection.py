"""
A03: Injection Examples
OWASP Top 10 2021

Simple SQL injection demonstration with one vulnerable endpoint.
DO NOT use in production!
"""

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

class InjectionDemo:
    def __init__(self):
        self.db_name = "users.db"
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database with sample data."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                salary INTEGER DEFAULT 0
            )
        ''')
        
        # Clear and insert sample data
        cursor.execute('DELETE FROM users')
        sample_users = [
            ('admin', 'admin@company.com', 'admin123', 'admin', 150000),
            ('alice', 'alice@company.com', 'password123', 'user', 75000),
            ('bob', 'bob@company.com', 'secret456', 'user', 65000)
        ]
        
        cursor.executemany(
            'INSERT INTO users (username, email, password, role, salary) VALUES (?, ?, ?, ?, ?)',
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
    VULNERABLE: Get user by ID - susceptible to SQL injection
    """
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation allows SQL injection
    user_id=int(user_id)
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3]
            })
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/secure/user/<user_id>')
def get_user_secure(user_id):
    """
    SECURE: Get user by ID using parameterized queries
    """
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    
    # try:
    #     # Validate input
    #     user_id = int(user_id)
    # except ValueError:
    #     return jsonify({'error': 'Invalid user ID format'}), 400
    
    # SECURE: Parameterized query prevents SQL injection
    query = "SELECT id, username, email, role FROM users WHERE id = ?"
    
    try:
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3]
            })
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    print("=== OWASP A03 Injection Demo ===")
    print("VULNERABLE endpoint: GET /api/user/<id>")
    print("SECURE endpoint:     GET /api/secure/user/<id>")
    print("Starting server on http://localhost:5002")
    
    app.run(debug=True, port=5002)