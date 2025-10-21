# A04: Insecure Design - Detailed Analysis

## Overview
This directory contains examples of insecure design vulnerabilities as outlined in the OWASP Top 10 2021 - A04 Insecure Design.

Insecure design refers to flaws in the architecture and design of software that lead to security vulnerabilities, representing missing or ineffective control design.

## Vulnerability Demonstrated

### `transfer_funds()` - Missing Authorization Controls

**Vulnerable Code:**
```python
@app.route('/transfer', methods=['POST'])
def transfer_funds():
    """
    Transfer money between accounts.
    Simple fund transfer functionality.
    """
    from_account = int(request.form['from_account'])
    to_account = int(request.form['to_account'])
    amount = int(request.form['amount'])
    
    # Direct transfer without authorization checks
    if users[from_account]['balance'] >= amount:
        users[from_account]['balance'] -= amount
        users[to_account]['balance'] += amount
        return jsonify({"message": "Transfer successful"})
    else:
        return jsonify({"error": "Insufficient funds"}), 400
```

**Vulnerabilities Present:**
- **CWE-862: Missing Authorization**
- **CWE-863: Incorrect Authorization**
- **CWE-284: Improper Access Control**

**Issues:**
1. **No User Authentication**: System doesn't verify who is making the transfer
2. **Missing Authorization**: No check if the user owns the source account
3. **No Transaction Limits**: No daily/monthly transfer limits
4. **Missing Audit Trail**: No logging of financial transactions
5. **No Multi-Factor Authentication**: High-value transfers should require additional verification

**Real-World Impact:**
- Attackers can transfer money from any account to their own accounts
- Complete financial fraud without any authentication
- No way to trace unauthorized transactions
- Regulatory compliance violations (PCI DSS, SOX)

**Secure Solution:**
```python
from functools import wraps
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_mfa_for_high_value(amount):
    """Require MFA for transfers over $1000"""
    if amount > 1000:
        mfa_token = request.form.get('mfa_token')
        if not verify_mfa_token(session['user_id'], mfa_token):
            return False
    return True

@app.route('/transfer', methods=['POST'])
@require_auth
def transfer_funds_secure():
    """Secure fund transfer with proper authorization."""
    try:
        from_account = int(request.form['from_account'])
        to_account = int(request.form['to_account'])
        amount = int(request.form['amount'])
        user_id = session['user_id']
        
        # Input validation
        if amount <= 0:
            return jsonify({"error": "Invalid amount"}), 400
        
        if amount > 10000:  # Daily limit
            return jsonify({"error": "Amount exceeds daily limit"}), 400
        
        # Authorization check - user must own the source account
        if not user_owns_account(user_id, from_account):
            logger.warning(f"Unauthorized transfer attempt by user {user_id} from account {from_account}")
            return jsonify({"error": "Unauthorized"}), 403
        
        # Check daily transfer limit
        daily_total = get_daily_transfer_total(user_id)
        if daily_total + amount > 5000:  # $5000 daily limit
            return jsonify({"error": "Daily transfer limit exceeded"}), 400
        
        # MFA check for high-value transfers
        if not require_mfa_for_high_value(amount):
            return jsonify({"error": "MFA verification required"}), 403
        
        # Verify account exists and has sufficient funds
        if from_account not in users or to_account not in users:
            return jsonify({"error": "Invalid account"}), 400
        
        if users[from_account]['balance'] < amount:
            return jsonify({"error": "Insufficient funds"}), 400
        
        # Perform transfer with transaction logging
        transaction_id = generate_transaction_id()
        
        users[from_account]['balance'] -= amount
        users[to_account]['balance'] += amount
        
        # Log the transaction
        log_transaction(transaction_id, user_id, from_account, to_account, amount)
        
        logger.info(f"Transfer completed: {transaction_id} - User {user_id} transferred ${amount} from {from_account} to {to_account}")
        
        return jsonify({
            "message": "Transfer successful",
            "transaction_id": transaction_id,
            "new_balance": users[from_account]['balance']
        })
        
    except ValueError:
        return jsonify({"error": "Invalid input format"}), 400
    except Exception as e:
        logger.error(f"Transfer error: {e}")
        return jsonify({"error": "Transfer failed"}), 500

def user_owns_account(user_id, account_id):
    """Verify user ownership of account"""
    # In real implementation, check database
    return users.get(account_id, {}).get('owner_id') == user_id

def get_daily_transfer_total(user_id):
    """Get total transfers for user today"""
    # In real implementation, query transaction database
    return 0  # Simplified for demo

def verify_mfa_token(user_id, token):
    """Verify MFA token"""
    # In real implementation, verify TOTP/SMS token
    return token == "123456"  # Simplified for demo

def generate_transaction_id():
    """Generate unique transaction ID"""
    import uuid
    return str(uuid.uuid4())

def log_transaction(transaction_id, user_id, from_account, to_account, amount):
    """Log transaction for audit trail"""
    transaction_log = {
        'id': transaction_id,
        'user_id': user_id,
        'from_account': from_account,
        'to_account': to_account,
        'amount': amount,
        'timestamp': datetime.now().isoformat(),
        'ip_address': request.remote_addr
    }
    # In real implementation, store in secure audit database
    logger.info(f"Transaction logged: {transaction_log}")
```

**Why This Solution Works:**
- **Authentication Required**: Users must be logged in to transfer funds
- **Authorization Checks**: Users can only transfer from accounts they own
- **Input Validation**: Validates all inputs and enforces limits
- **Multi-Factor Authentication**: High-value transfers require additional verification
- **Audit Logging**: All transactions are logged for compliance and investigation
- **Rate Limiting**: Daily transfer limits prevent abuse
- **Error Handling**: Proper error handling without information disclosure

## Design Security Principles

### 1. Defense in Depth
```python
# Multiple layers of security
@require_auth                    # Layer 1: Authentication
@require_account_ownership      # Layer 2: Authorization  
@require_mfa_for_high_value    # Layer 3: Additional verification
@rate_limit                    # Layer 4: Rate limiting
def secure_operation():
    pass
```

### 2. Principle of Least Privilege
```python
def get_user_permissions(user_role):
    """Grant minimum necessary permissions"""
    permissions = {
        'user': ['view_own_account', 'transfer_own_funds'],
        'manager': ['view_team_accounts', 'approve_transfers'],
        'admin': ['view_all_accounts', 'system_config']
    }
    return permissions.get(user_role, [])
```

### 3. Fail Securely
```python
def authorize_action(user_id, action, resource):
    """Default to deny access on any error"""
    try:
        if not user_exists(user_id):
            return False  # Fail securely
        
        permissions = get_user_permissions(user_id)
        return action in permissions
    except Exception:
        return False  # Always fail securely
```

## Prevention Strategies

1. **Secure Design Patterns**: Use established secure design patterns
2. **Threat Modeling**: Identify threats during design phase
3. **Security Requirements**: Define security requirements early
4. **Code Review**: Review design and implementation for security flaws
5. **Penetration Testing**: Test the design with security professionals

## References
- [OWASP Secure Design Principles](https://owasp.org/www-project-developer-guide/draft/design/principles/)
- [OWASP Application Security Architecture](https://owasp.org/www-project-developer-guide/draft/design/architecture/)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)

---
**⚠️ WARNING: The code in this directory contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**
