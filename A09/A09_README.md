2# A09: Security Logging and Monitoring Failures - Detailed Analysis

## Overview
This directory contains examples of security logging and monitoring failures as outlined in the OWASP Top 10 2021 - A09 Security Logging and Monitoring Failures.

Insufficient logging and monitoring can lead to undetected security breaches and make incident response difficult.

## Vulnerabilities Demonstrated

### 1. `login()` - Missing Authentication Logging

**Vulnerable Code:**
```python
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
```

**Vulnerabilities Present:**
- **CWE-778: Insufficient Logging**
- **CWE-223: Omission of Security-relevant Information**

**Issues:**
1. **No Login Attempt Logging**: Failed logins not recorded
2. **No Success Logging**: Successful logins not tracked
3. **Missing Context**: No IP address, timestamp, or user agent logging
4. **No Alerting**: No alerts for suspicious activity

**Secure Solution:**
```python
import logging
from datetime import datetime
import json
from collections import defaultdict, deque
import threading

# Configure comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/app/security.log'),
        logging.StreamHandler()
    ]
)

# Create specialized loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')
access_logger = logging.getLogger('access')

# Security event monitoring
class SecurityMonitor:
    def __init__(self):
        self.failed_logins = defaultdict(lambda: deque(maxlen=10))
        self.suspicious_ips = set()
        self.lock = threading.Lock()
    
    def record_failed_login(self, username, ip_address, user_agent):
        """Record and analyze failed login attempts"""
        with self.lock:
            timestamp = datetime.utcnow()
            
            # Record the attempt
            self.failed_logins[ip_address].append({
                'username': username,
                'timestamp': timestamp,
                'user_agent': user_agent
            })
            
            # Check for suspicious patterns
            recent_failures = len([
                attempt for attempt in self.failed_logins[ip_address]
                if (timestamp - attempt['timestamp']).seconds < 300  # 5 minutes
            ])
            
            if recent_failures >= 5:
                self.suspicious_ips.add(ip_address)
                self.alert_suspicious_activity(ip_address, username, recent_failures)
    
    def alert_suspicious_activity(self, ip_address, username, failure_count):
        """Alert on suspicious activity"""
        alert_data = {
            'alert_type': 'brute_force_attempt',
            'ip_address': ip_address,
            'target_username': username,
            'failure_count': failure_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        security_logger.critical(f"SECURITY ALERT: {json.dumps(alert_data)}")
        
        # In production, send to SIEM/alerting system
        self.send_security_alert(alert_data)
    
    def send_security_alert(self, alert_data):
        """Send alert to security team (implement with actual alerting system)"""
        # Example: send to Slack, email, SIEM, etc.
        pass

# Initialize security monitor
security_monitor = SecurityMonitor()

@app.route('/login_secure', methods=['POST'])
def login_secure():
    """Login with comprehensive security logging"""
    # Extract request information
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.utcnow()
    
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Log access attempt
    access_logger.info(json.dumps({
        'event': 'login_attempt',
        'username': username,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'timestamp': timestamp.isoformat()
    }))
    
    # Validate credentials
    if username in users and users[username] == password:
        # Successful login
        session['user'] = username
        session['login_time'] = timestamp.isoformat()
        
        # Log successful authentication
        security_logger.info(json.dumps({
            'event': 'authentication_success',
            'username': username,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'session_id': session.get('session_id'),
            'timestamp': timestamp.isoformat()
        }))
        
        # Audit log for compliance
        audit_logger.info(json.dumps({
            'event': 'user_login',
            'user_id': username,
            'ip_address': ip_address,
            'timestamp': timestamp.isoformat(),
            'result': 'success'
        }))
        
        return jsonify({"message": "Login successful"})
    
    else:
        # Failed login
        security_monitor.record_failed_login(username, ip_address, user_agent)
        
        # Log failed authentication
        security_logger.warning(json.dumps({
            'event': 'authentication_failure',
            'username': username,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'timestamp': timestamp.isoformat(),
            'reason': 'invalid_credentials'
        }))
        
        # Audit log
        audit_logger.info(json.dumps({
            'event': 'user_login',
            'user_id': username,
            'ip_address': ip_address,
            'timestamp': timestamp.isoformat(),
            'result': 'failure'
        }))
        
        return jsonify({"error": "Invalid credentials"}), 401
```

### 2. `delete_user()` - Missing Audit Trail

**Vulnerable Code:**
```python
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
```

**Vulnerabilities Present:**
- **CWE-778: Insufficient Logging**
- **CWE-223: Omission of Security-relevant Information**

**Issues:**
1. **No Audit Trail**: Critical administrative actions not logged
2. **Missing Context**: No record of who performed the action
3. **No Approval Workflow**: No verification or approval process
4. **Irreversible Action**: No backup or recovery mechanism

**Secure Solution:**
```python
from functools import wraps

def audit_critical_action(action_type):
    """Decorator to audit critical administrative actions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Extract request context
            admin_user = session.get('user')
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            timestamp = datetime.utcnow()
            request_data = request.get_json() or {}
            
            # Pre-action audit log
            audit_id = str(uuid.uuid4())
            audit_logger.info(json.dumps({
                'audit_id': audit_id,
                'event': f'{action_type}_initiated',
                'admin_user': admin_user,
                'ip_address': ip_address,
                'timestamp': timestamp.isoformat(),
                'request_data': request_data
            }))
            
            try:
                # Execute the function
                result = f(*args, **kwargs)
                
                # Post-action audit log
                audit_logger.info(json.dumps({
                    'audit_id': audit_id,
                    'event': f'{action_type}_completed',
                    'admin_user': admin_user,
                    'ip_address': ip_address,
                    'timestamp': datetime.utcnow().isoformat(),
                    'result': 'success'
                }))
                
                return result
                
            except Exception as e:
                # Error audit log
                audit_logger.error(json.dumps({
                    'audit_id': audit_id,
                    'event': f'{action_type}_failed',
                    'admin_user': admin_user,
                    'ip_address': ip_address,
                    'timestamp': datetime.utcnow().isoformat(),
                    'error': str(e)
                }))
                raise
        
        return decorated_function
    return decorator

@app.route('/admin/delete_user_secure', methods=['DELETE'])
@require_admin_auth
@audit_critical_action('user_deletion')
def delete_user_secure():
    """Secure user deletion with comprehensive logging and safeguards"""
    data = request.get_json()
    
    if not data or 'username' not in data:
        return jsonify({"error": "Username required"}), 400
    
    username = data['username']
    admin_user = session['user']
    
    # Prevent self-deletion
    if username == admin_user:
        security_logger.warning(json.dumps({
            'event': 'self_deletion_attempt',
            'admin_user': admin_user,
            'timestamp': datetime.utcnow().isoformat()
        }))
        return jsonify({"error": "Cannot delete own account"}), 400
    
    # Check if user exists
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    
    # Create backup before deletion
    user_backup = {
        'username': username,
        'data': users[username].copy(),
        'deleted_by': admin_user,
        'deleted_at': datetime.utcnow().isoformat(),
        'ip_address': request.remote_addr
    }
    
    # Store backup (implement proper backup storage)
    store_user_backup(user_backup)
    
    # Perform deletion
    del users[username]
    
    # Comprehensive logging
    security_logger.info(json.dumps({
        'event': 'user_deleted',
        'deleted_user': username,
        'admin_user': admin_user,
        'ip_address': request.remote_addr,
        'timestamp': datetime.utcnow().isoformat(),
        'backup_created': True
    }))
    
    # Compliance audit log
    audit_logger.info(json.dumps({
        'event': 'data_deletion',
        'data_type': 'user_account',
        'data_subject': username,
        'processor': admin_user,
        'legal_basis': data.get('legal_basis', 'administrative_action'),
        'timestamp': datetime.utcnow().isoformat()
    }))
    
    return jsonify({
        "message": "User deleted successfully",
        "backup_id": user_backup.get('backup_id')
    })

def store_user_backup(backup_data):
    """Store user backup securely"""
    backup_data['backup_id'] = str(uuid.uuid4())
    # In production, store in secure, encrypted backup system
    pass
```

### 3. `transfer()` - Missing Financial Transaction Logging

**Vulnerable Code:**
```python
@app.route('/transfer', methods=['POST'])
def transfer():
    """Financial transaction without audit logging."""
    amount = request.json['amount']
    to_account = request.json['to_account']
    
    # Process transfer without logging
    # No audit trail for financial transactions!
    return jsonify({"message": f"Transferred ${amount} to {to_account}"})
```

**Secure Solution:**
```python
@app.route('/transfer_secure', methods=['POST'])
@require_auth
def transfer_secure():
    """Secure financial transfer with comprehensive audit logging"""
    data = request.get_json()
    user_id = session['user']
    
    # Extract transaction details
    from_account = data.get('from_account')
    to_account = data.get('to_account')
    amount = data.get('amount')
    
    # Generate transaction ID
    transaction_id = str(uuid.uuid4())
    timestamp = datetime.utcnow()
    
    # Pre-transaction logging
    audit_logger.info(json.dumps({
        'event': 'transaction_initiated',
        'transaction_id': transaction_id,
        'user_id': user_id,
        'from_account': from_account,
        'to_account': to_account,
        'amount': amount,
        'ip_address': request.remote_addr,
        'timestamp': timestamp.isoformat()
    }))
    
    try:
        # Validate and process transaction
        if not validate_transaction(user_id, from_account, to_account, amount):
            raise TransactionError("Transaction validation failed")
        
        # Execute transaction
        result = execute_transfer(from_account, to_account, amount)
        
        # Post-transaction logging
        audit_logger.info(json.dumps({
            'event': 'transaction_completed',
            'transaction_id': transaction_id,
            'user_id': user_id,
            'from_account': from_account,
            'to_account': to_account,
            'amount': amount,
            'new_balance': result.get('new_balance'),
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'success'
        }))
        
        # Financial compliance logging
        financial_logger = logging.getLogger('financial')
        financial_logger.info(json.dumps({
            'transaction_id': transaction_id,
            'type': 'transfer',
            'amount': amount,
            'currency': 'USD',
            'from_account': from_account,
            'to_account': to_account,
            'user_id': user_id,
            'timestamp': timestamp.isoformat(),
            'regulatory_flags': check_regulatory_requirements(amount, from_account, to_account)
        }))
        
        return jsonify({
            "message": "Transfer completed successfully",
            "transaction_id": transaction_id
        })
        
    except Exception as e:
        # Error logging
        audit_logger.error(json.dumps({
            'event': 'transaction_failed',
            'transaction_id': transaction_id,
            'user_id': user_id,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }))
        
        return jsonify({"error": "Transaction failed"}), 500
```

## Security Monitoring Implementation

### Real-time Security Monitoring
```python
class SecurityEventProcessor:
    def __init__(self):
        self.event_patterns = {
            'brute_force': self.detect_brute_force,
            'privilege_escalation': self.detect_privilege_escalation,
            'data_exfiltration': self.detect_data_exfiltration
        }
    
    def process_event(self, event):
        """Process security events for pattern detection"""
        for pattern_name, detector in self.event_patterns.items():
            if detector(event):
                self.trigger_alert(pattern_name, event)
    
    def detect_brute_force(self, event):
        """Detect brute force attack patterns"""
        if event.get('event') == 'authentication_failure':
            # Check for multiple failures from same IP
            return self.check_failure_rate(event['ip_address'])
        return False
    
    def detect_privilege_escalation(self, event):
        """Detect privilege escalation attempts"""
        if event.get('event') == 'authorization_failure':
            # Check for repeated attempts to access admin functions
            return self.check_escalation_attempts(event['user_id'])
        return False
    
    def trigger_alert(self, pattern_type, event):
        """Trigger security alert"""
        alert = {
            'alert_type': pattern_type,
            'severity': 'high',
            'event_data': event,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        security_logger.critical(f"SECURITY ALERT: {json.dumps(alert)}")
```

## Log Management Best Practices

### 1. Structured Logging Configuration
```python
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

### 2. Log Retention and Rotation
```python
import logging.handlers

# Configure log rotation
handler = logging.handlers.RotatingFileHandler(
    '/var/log/app/security.log',
    maxBytes=100*1024*1024,  # 100MB
    backupCount=10
)

# Configure time-based rotation
time_handler = logging.handlers.TimedRotatingFileHandler(
    '/var/log/app/audit.log',
    when='midnight',
    interval=1,
    backupCount=365  # Keep 1 year of logs
)
```

## Prevention Strategies

1. **Comprehensive Logging**: Log all security-relevant events
2. **Structured Logs**: Use consistent, machine-readable log formats
3. **Real-time Monitoring**: Implement automated threat detection
4. **Log Integrity**: Protect logs from tampering
5. **Retention Policies**: Maintain logs for compliance requirements
6. **Incident Response**: Establish procedures for security events

## References
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Logging Best Practices](https://www.sans.org/white-papers/logging/)

---
**⚠️ WARNING: The code in this directory contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**
