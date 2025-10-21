from flask import Flask, request, jsonify, session
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'weak_secret_key'

users_db = {
    1: {'id': 1, 'username': 'admin', 'role': 'admin', 'email': 'admin@example.com'},
    2: {'id': 2, 'username': 'user1', 'role': 'user', 'email': 'user1@example.com'},
    3: {'id': 3, 'username': 'user2', 'role': 'user', 'email': 'user2@example.com'}
}

posts_db = {
    1: {'id': 1, 'user_id': 1, 'content': 'Admin post'},
    2: {'id': 2, 'user_id': 2, 'content': 'User1 private post'},
    3: {'id': 3, 'user_id': 3, 'content': 'User2 private post'}
}


class AccessControlExamples:

    # Example 1: Violation of the principle of least privilege or deny by default
    @staticmethod
    @app.route('/admin/dashboard')
    def admin_dashboard():
        return jsonify({
            'message': 'Welcome to admin dashboard',
            'users': users_db,
            'system_config': {'debug': True, 'api_keys': ['secret123']}
        })

    # Example 2: Bypassing access control checks (parameter tampering)
    @staticmethod
    @app.route('/user/profile')
    def user_profile():
        user_id = request.args.get('user_id', type=int)
        user = users_db.get(user_id)
        if user:
            return jsonify(user)
        return jsonify({'error': 'Not found'}), 404

    # Example 3: Insecure direct object references (IDOR)
    @staticmethod
    @app.route('/account/<int:account_id>/balance')
    def account_balance(account_id):
        balances = {1: 50000, 2: 30000, 3: 75000}
        balance = balances.get(account_id)
        if balance is not None:
            return jsonify({
                'account_id': account_id,
                'balance': balance
            })
        return jsonify({'error': 'Not found'}), 404

    # Example 4: Missing access controls for POST, PUT and DELETE
    @staticmethod
    @app.route('/api/posts/<int:post_id>', methods=['DELETE'])
    def delete_post(post_id):
        if post_id in posts_db:
            del posts_db[post_id]
            return jsonify({'message': 'Post deleted'})
        return jsonify({'error': 'Not found'}), 404

    # Example 5: Elevation of privilege
    @staticmethod
    @app.route('/promote')
    def promote_user():
        user_id = request.args.get('user_id', type=int)
        new_role = request.args.get('role', 'user')

        if user_id in users_db:
            users_db[user_id]['role'] = new_role
            return jsonify({
                'message': f'User {user_id} promoted to {new_role}',
                'user': users_db[user_id]
            })
        return jsonify({'error': 'User not found'}), 404

    # Example 6: Metadata manipulation (JWT)
    @staticmethod
    @app.route('/login')
    def login():
        username = request.args.get('username')
        user = next((u for u in users_db.values() if u['username'] == username), None)

        if user:
            token = jwt.encode(
                {
                    'user_id': user['id'],
                    'role': user['role'],
                    'exp': datetime.utcnow() + timedelta(hours=24)
                },
                None,
                algorithm='none'
            )
            return jsonify({'token': token})
        return jsonify({'error': 'Invalid credentials'}), 401

    @staticmethod
    @app.route('/verify_token')
    def verify_token():
        token = request.args.get('token')
        try:
            payload = jwt.decode(token, options={'verify_signature': False})
            return jsonify({
                'message': 'Token valid',
                'user_data': payload
            })
        except:
            return jsonify({'error': 'Invalid token'}), 401

    # Example 7: CORS misconfiguration
    @staticmethod
    @app.route('/api/sensitive-data')
    def get_sensitive_data():
        response = jsonify({
            'api_keys': ['sk_live_123456'],
            'internal_data': 'sensitive information'
        })
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    # Example 8: Force browsing
    @staticmethod
    @app.route('/backup/database.sql')
    def database_backup():
        return """
        -- Database Backup
        CREATE TABLE users (
            id INT PRIMARY KEY,
            username VARCHAR(50),
            password_hash VARCHAR(255),
            api_key VARCHAR(100)
        );

        INSERT INTO users VALUES (1, 'admin', '$2b$12$...', 'sk_live_secret123');
        """


if __name__ == '__main__':

    app.run(debug=True, port=5001)