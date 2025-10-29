"""
A02: Cryptographic Failures Examples
OWASP Top 10 2021

This module demonstrates common cryptographic failures using Flask and SQLite.
These are intentionally vulnerable implementations - DO NOT use in production!
"""

from flask import Flask, request, jsonify
import sqlite3
import hashlib
import base64
from cryptography.fernet import Fernet
import bcrypt
import secrets

app = Flask(__name__)

class CryptographicFailuresDemo:
    """
    Demonstration class showing common cryptographic failures.
    """
    
    def __init__(self):
        self.db_name = "users_crypto.db"
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database with sample data."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                credit_card TEXT
            )
        ''')
        
        # Clear existing data
        cursor.execute('DELETE FROM users')
        
        # Insert sample users with weak crypto
        sample_users = [
            ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@example.com', 
             base64.b64encode('4532-1234-5678-9012'.encode()).decode()),
            ('alice', hashlib.md5('password'.encode()).hexdigest(), 'alice@example.com', 
             base64.b64encode('5555-4444-3333-2222'.encode()).decode())
        ]
        
        cursor.executemany(
            'INSERT INTO users (username, password, email, credit_card) VALUES (?, ?, ?, ?)',
            sample_users
        )
        
        conn.commit()
        conn.close()
        print("Database initialized with vulnerable crypto")

# Initialize the demo
demo = CryptographicFailuresDemo()

@app.route('/register', methods=['POST'])
def register():
    """User registration with weak MD5 password hashing."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    # Vulnerable: MD5 password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            (username, password_hash, email)
        )
        conn.commit()
        return jsonify({'message': 'User registered', 'hash': password_hash})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username exists'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    """Login with weak password verification."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Vulnerable: MD5 comparison
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id FROM users WHERE username = ? AND password = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'message': 'Login successful', 'user_id': user[0]})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/profile/<int:user_id>')
def get_profile(user_id):
    """Get user profile with weak encryption."""
    conn = sqlite3.connect(demo.db_name)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT username, email, credit_card FROM users WHERE id = ?',
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        username, email, encrypted_cc = user
        # Vulnerable: Simple base64 "encryption"
        credit_card = base64.b64decode(encrypted_cc).decode() if encrypted_cc else None
        
        return jsonify({
            'username': username,
            'email': email,
            'credit_card': credit_card
        })
    return jsonify({'error': 'User not found'}), 404

# Secure Implementation Solutions
class CryptographicSolutions:
    """Secure implementations that fix cryptographic failures."""
    
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.secure_db = "users_secure.db"
        self.init_secure_database()
    
    def init_secure_database(self):
        """Initialize secure database."""
        conn = sqlite3.connect(self.secure_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secure_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                credit_card TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

secure_crypto = CryptographicSolutions()

@app.route('/secure/register', methods=['POST'])
def secure_register():
    """Secure user registration with bcrypt."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    # Secure: bcrypt password hashing
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO secure_users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, password_hash.decode('utf-8'), email)
        )
        conn.commit()
        return jsonify({'message': 'User registered securely'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username exists'}), 400
    finally:
        conn.close()

@app.route('/secure/login', methods=['POST'])
def secure_login():
    """Secure login with bcrypt verification."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, password_hash FROM secure_users WHERE username = ?',
        (username,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        return jsonify({'message': 'Login successful', 'user_id': user[0]})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/secure/profile/<int:user_id>')
def secure_get_profile(user_id):
    """Get user profile with strong encryption."""
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT username, email, credit_card FROM secure_users WHERE id = ?',
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        username, email, encrypted_cc = user
        # Secure: Fernet encryption/decryption
        credit_card = None
        if encrypted_cc:
            try:
                credit_card = secure_crypto.fernet.decrypt(encrypted_cc.encode()).decode()
            except:
                credit_card = "Decryption failed"
        
        return jsonify({
            'username': username,
            'email': email,
            'credit_card': credit_card
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/secure/update_payment', methods=['POST'])
def secure_update_payment():
    """Update payment info with strong encryption."""
    data = request.get_json()
    user_id = data.get('user_id')
    credit_card = data.get('credit_card')
    
    # Secure: Fernet encryption
    encrypted_cc = secure_crypto.fernet.encrypt(credit_card.encode()).decode()
    
    conn = sqlite3.connect(secure_crypto.secure_db)
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE secure_users SET credit_card = ? WHERE id = ?',
        (encrypted_cc, user_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Payment info updated securely'})

if __name__ == '__main__':
    print("=== OWASP A02 Cryptographic Failures Demo ===")
    print("Vulnerable endpoints: /register, /login, /profile/<id>")
    print("Secure endpoints: /secure/register, /secure/login, /secure/profile/<id>")
    print("Starting server on http://localhost:5002")
    
    app.run(debug=True, port=5002)