"""
A04: Insecure Design Example
OWASP Top 10 2021

Simple example of insecure design flaws.
DO NOT use in production!
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

# Simple user data store
users = {
    1: {"name": "Alice", "balance": 1000, "role": "user"},
    2: {"name": "Bob", "balance": 500, "role": "user"},
    3: {"name": "Admin", "balance": 10000, "role": "admin"}
}

@app.route('/transfer', methods=['POST'])
def transfer_funds():
    """
    Transfer money between accounts.
    Simple fund transfer functionality.
    """
    data = request.get_json()
    from_account = int(data.get('from_account', 1))  # Default to account 1 if not provided
    to_account = int(data.get('to_account', 2))      # Default to account 2 if not provided
    amount = int(data['amount'])
    
    # Direct transfer without authorization checks
    if users[from_account]['balance'] >= amount:
        users[from_account]['balance'] -= amount
        users[to_account]['balance'] += amount
        return jsonify({
            "message": "Transfer successful", 
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount
        })
    else:
        return jsonify({"error": "Insufficient funds"}), 400

@app.route('/user/<int:user_id>')
def get_user(user_id):
    """Get user information - no access control."""
    return jsonify(users.get(user_id, {"error": "User not found"}))

if __name__ == '__main__':
    app.run(debug=True, port=5002)
