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

# Secure Design Solutions
@app.route('/secure/transfer', methods=['POST'])
def secure_transfer_funds():
    """
    Secure fund transfer with proper authorization and validation.
    """
    data = request.get_json()
    
    # Input validation
    if not data or 'from_account' not in data or 'to_account' not in data or 'amount' not in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        from_account = int(data['from_account'])
        to_account = int(data['to_account'])
        amount = float(data['amount'])
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid data types"}), 400
    
    # Business logic validation
    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400
    
    if from_account == to_account:
        return jsonify({"error": "Cannot transfer to same account"}), 400
    
    if from_account not in users or to_account not in users:
        return jsonify({"error": "Invalid account"}), 400
    
    # Authorization check (simplified - in real app, check session/token)
    current_user = request.headers.get('X-User-ID', type=int)
    if current_user != from_account and users.get(current_user, {}).get('role') != 'admin':
        return jsonify({"error": "Unauthorized transfer"}), 403
    
    # Transfer limits
    if amount > 1000 and users[from_account]['role'] != 'admin':
        return jsonify({"error": "Transfer limit exceeded"}), 400
    
    # Execute transfer
    if users[from_account]['balance'] >= amount:
        users[from_account]['balance'] -= amount
        users[to_account]['balance'] += amount
        return jsonify({
            "message": "Transfer successful", 
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "new_balance": users[from_account]['balance']
        })
    else:
        return jsonify({"error": "Insufficient funds"}), 400

@app.route('/secure/user/<int:user_id>')
def get_user_secure(user_id):
    """Get user information with access control."""
    current_user = request.headers.get('X-User-ID', type=int)
    
    # Users can only see their own data, admins can see all
    if current_user != user_id and users.get(current_user, {}).get('role') != 'admin':
        return jsonify({"error": "Access denied"}), 403
    
    user = users.get(user_id)
    if user:
        # Don't expose sensitive data
        safe_user = {
            "name": user["name"],
            "role": user["role"]
        }
        # Only show balance to account owner or admin
        if current_user == user_id or users.get(current_user, {}).get('role') == 'admin':
            safe_user["balance"] = user["balance"]
        return jsonify(safe_user)
    
    return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5002)
