# A10: Server-Side Request Forgery (SSRF) - Detailed Analysis

## Overview
This directory contains examples of Server-Side Request Forgery (SSRF) vulnerabilities as outlined in the OWASP Top 10 2021 - A10 Server-Side Request Forgery (SSRF).

SSRF vulnerabilities occur when a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to force the application to send requests to unintended locations.

## Vulnerabilities Demonstrated

### 1. `fetch_url()` - Basic SSRF Vulnerability

**Vulnerable Code:**
```python
@app.route('/fetch', methods=['GET'])
def fetch_url():
    """Fetch content from user-provided URL."""
    url = request.args.get('url')
    
    if not url:
        return jsonify({"error": "URL parameter required"}), 400
    
    try:
        # Fetch URL without validation - SSRF vulnerability!
        response = requests.get(url, timeout=10)
        return jsonify({
            "status_code": response.status_code,
            "content": response.text[:500]  # First 500 chars
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

**Vulnerabilities Present:**
- **CWE-918: Server-Side Request Forgery (SSRF)**
- **CWE-20: Improper Input Validation**

**Attack Examples:**
```bash
# Access internal services
GET /fetch?url=http://localhost:8080/admin

# Access cloud metadata (AWS)
GET /fetch?url=http://169.254.169.254/latest/meta-data/

# Port scanning internal network
GET /fetch?url=http://192.168.1.1:22

# File system access (if supported)
GET /fetch?url=file:///etc/passwd

# Access internal databases
GET /fetch?url=http://internal-db:5432/
```

**Real-World Impact:**
- Access to internal services and APIs
- Cloud metadata exposure (AWS credentials, etc.)
- Internal network reconnaissance and port scanning
- Bypass of firewalls and access controls
- Potential remote code execution on internal systems

**Secure Solution:**
```python
import ipaddress
from urllib.parse import urlparse
import socket
import requests

class SSRFProtection:
    def __init__(self):
        # Define allowed protocols
        self.allowed_schemes = ['http', 'https']
        
        # Define blocked IP ranges (RFC 1918 private networks, etc.)
        self.blocked_networks = [
            ipaddress.ip_network('10.0.0.0/8'),      # Private Class A
            ipaddress.ip_network('172.16.0.0/12'),   # Private Class B
            ipaddress.ip_network('192.168.0.0/16'),  # Private Class C
            ipaddress.ip_network('127.0.0.0/8'),     # Loopback
            ipaddress.ip_network('169.254.0.0/16'),  # Link-local
            ipaddress.ip_network('224.0.0.0/4'),     # Multicast
            ipaddress.ip_network('::1/128'),         # IPv6 loopback
            ipaddress.ip_network('fc00::/7'),        # IPv6 private
            ipaddress.ip_network('fe80::/10'),       # IPv6 link-local
        ]
        
        # Define allowed domains (whitelist approach)
        self.allowed_domains = [
            'api.github.com',
            'httpbin.org',
            'jsonplaceholder.typicode.com'
        ]
        
        # Define blocked ports
        self.blocked_ports = [22, 23, 25, 53, 80, 135, 139, 445, 1433, 3306, 5432, 6379]
    
    def validate_url(self, url):
        """Comprehensive URL validation to prevent SSRF"""
        try:
            parsed = urlparse(url)
            
            # Check protocol
            if parsed.scheme not in self.allowed_schemes:
                raise SSRFError(f"Protocol '{parsed.scheme}' not allowed")
            
            # Check for missing hostname
            if not parsed.hostname:
                raise SSRFError("Invalid URL: missing hostname")
            
            # Resolve hostname to IP
            try:
                ip_addresses = socket.getaddrinfo(parsed.hostname, None)
                resolved_ips = [ip[4][0] for ip in ip_addresses]
            except socket.gaierror:
                raise SSRFError("Failed to resolve hostname")
            
            # Check each resolved IP
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    
                    # Check against blocked networks
                    for network in self.blocked_networks:
                        if ip in network:
                            raise SSRFError(f"Access to {ip} is blocked (private/internal network)")
                    
                except ValueError:
                    raise SSRFError(f"Invalid IP address: {ip_str}")
            
            # Check port (if specified)
            if parsed.port:
                if parsed.port in self.blocked_ports:
                    raise SSRFError(f"Port {parsed.port} is blocked")
            
            # Domain whitelist check
            if not any(parsed.hostname.endswith(domain) for domain in self.allowed_domains):
                raise SSRFError(f"Domain '{parsed.hostname}' not in whitelist")
            
            return True
            
        except Exception as e:
            if isinstance(e, SSRFError):
                raise
            else:
                raise SSRFError(f"URL validation failed: {str(e)}")

# Initialize SSRF protection
ssrf_protection = SSRFProtection()

@app.route('/fetch_secure', methods=['GET'])
@require_auth
def fetch_url_secure():
    """Secure URL fetching with SSRF protection"""
    url = request.args.get('url')
    
    if not url:
        return jsonify({"error": "URL parameter required"}), 400
    
    # Input validation
    if len(url) > 2048:  # Reasonable URL length limit
        return jsonify({"error": "URL too long"}), 400
    
    try:
        # Validate URL against SSRF attacks
        ssrf_protection.validate_url(url)
        
        # Configure secure request
        session = requests.Session()
        session.max_redirects = 3  # Limit redirects
        
        # Set secure headers
        headers = {
            'User-Agent': 'SecureApp/1.0',
            'Accept': 'application/json, text/plain',
        }
        
        # Make request with security controls
        response = session.get(
            url,
            headers=headers,
            timeout=(5, 10),  # (connect, read) timeouts
            allow_redirects=True,
            verify=True,  # Verify SSL certificates
            stream=True   # Stream for size checking
        )
        
        # Check response size
        max_size = 1024 * 1024  # 1MB limit
        content = b''
        
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > max_size:
                return jsonify({"error": "Response too large"}), 400
        
        # Validate content type
        content_type = response.headers.get('content-type', '').lower()
        allowed_types = ['application/json', 'text/plain', 'text/html']
        
        if not any(content_type.startswith(allowed) for allowed in allowed_types):
            return jsonify({"error": "Content type not allowed"}), 400
        
        # Log the request for monitoring
        logger.info(f"External URL fetched by user {session.get('user_id')}: {url}")
        
        return jsonify({
            "status_code": response.status_code,
            "content_type": content_type,
            "content": content.decode('utf-8', errors='ignore')[:500],
            "size": len(content)
        })
        
    except SSRFError as e:
        logger.warning(f"SSRF attempt blocked: {url} - {str(e)}")
        return jsonify({"error": f"Request blocked: {str(e)}"}), 400
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timeout"}), 408
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return jsonify({"error": "Request failed"}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

class SSRFError(Exception):
    pass
```

### 2. `webhook()` - SSRF via Webhook Callbacks

**Vulnerable Code:**
```python
@app.route('/webhook', methods=['POST'])
def webhook():
    """Process webhook by fetching callback URL."""
    callback_url = request.json.get('callback_url')
    data = request.json.get('data', {})
    
    # Send data to callback URL without validation
    try:
        response = requests.post(callback_url, json=data)
        return jsonify({"message": "Webhook processed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

**Vulnerabilities Present:**
- **CWE-918: Server-Side Request Forgery (SSRF)**
- **CWE-601: URL Redirection to Untrusted Site**

**Secure Solution:**
```python
import hmac
import hashlib
from datetime import datetime, timedelta

# Webhook security configuration
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', 'secure-webhook-secret')
WEBHOOK_TIMEOUT = 30  # seconds

class WebhookValidator:
    def __init__(self):
        self.allowed_callback_domains = [
            'webhooks.example.com',
            'api.trusted-partner.com'
        ]
    
    def validate_callback_url(self, url):
        """Validate webhook callback URL"""
        try:
            parsed = urlparse(url)
            
            # Must use HTTPS
            if parsed.scheme != 'https':
                raise WebhookError("Callback URL must use HTTPS")
            
            # Check domain whitelist
            if not any(parsed.hostname.endswith(domain) for domain in self.allowed_callback_domains):
                raise WebhookError(f"Callback domain '{parsed.hostname}' not allowed")
            
            # Additional SSRF protection
            ssrf_protection.validate_url(url)
            
            return True
            
        except SSRFError as e:
            raise WebhookError(f"SSRF protection: {str(e)}")
    
    def sign_payload(self, payload):
        """Create HMAC signature for webhook payload"""
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
        signature = hmac.new(
            WEBHOOK_SECRET.encode(),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

webhook_validator = WebhookValidator()

@app.route('/webhook_secure', methods=['POST'])
@require_auth
def webhook_secure():
    """Secure webhook processing with validation"""
    data = request.get_json()
    
    if not data or 'callback_url' not in data:
        return jsonify({"error": "Callback URL required"}), 400
    
    callback_url = data['callback_url']
    webhook_data = data.get('data', {})
    user_id = session['user_id']
    
    try:
        # Validate callback URL
        webhook_validator.validate_callback_url(callback_url)
        
        # Prepare secure payload
        payload = {
            'data': webhook_data,
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'webhook_id': str(uuid.uuid4())
        }
        
        # Sign the payload
        signature = webhook_validator.sign_payload(payload)
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'SecureApp-Webhook/1.0',
            'X-Webhook-Signature': signature,
            'X-Webhook-Timestamp': payload['timestamp']
        }
        
        # Make secure request
        response = requests.post(
            callback_url,
            json=payload,
            headers=headers,
            timeout=WEBHOOK_TIMEOUT,
            verify=True,
            allow_redirects=False  # Don't follow redirects
        )
        
        # Log webhook delivery
        logger.info(f"Webhook delivered: {callback_url} - Status: {response.status_code}")
        
        return jsonify({
            "message": "Webhook processed successfully",
            "webhook_id": payload['webhook_id'],
            "status_code": response.status_code
        })
        
    except WebhookError as e:
        logger.warning(f"Webhook validation failed: {callback_url} - {str(e)}")
        return jsonify({"error": str(e)}), 400
    except requests.exceptions.RequestException as e:
        logger.error(f"Webhook delivery failed: {callback_url} - {str(e)}")
        return jsonify({"error": "Webhook delivery failed"}), 500

class WebhookError(Exception):
    pass
```

### 3. `proxy()` - Open Proxy SSRF

**Vulnerable Code:**
```python
@app.route('/proxy')
def proxy():
    """Simple proxy service."""
    target = request.args.get('target')
    
    # Proxy request without URL validation
    response = requests.get(target)
    return response.content, response.status_code
```

**Secure Solution:**
```python
@app.route('/proxy_secure')
@require_admin_auth
def proxy_secure():
    """Secure proxy with strict controls"""
    target = request.args.get('target')
    
    if not target:
        return jsonify({"error": "Target URL required"}), 400
    
    # Admin-only proxy with strict whitelist
    allowed_proxy_targets = [
        'https://api.external-service.com',
        'https://cdn.trusted-partner.com'
    ]
    
    if target not in allowed_proxy_targets:
        logger.warning(f"Unauthorized proxy attempt: {target}")
        return jsonify({"error": "Target not allowed"}), 403
    
    try:
        # Proxy with security controls
        response = requests.get(
            target,
            timeout=10,
            verify=True,
            allow_redirects=False
        )
        
        # Filter response headers
        safe_headers = {
            'Content-Type': response.headers.get('Content-Type'),
            'Content-Length': response.headers.get('Content-Length')
        }
        
        logger.info(f"Proxy request: {target} - Status: {response.status_code}")
        
        return response.content, response.status_code, safe_headers
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Proxy request failed: {target} - {str(e)}")
        return jsonify({"error": "Proxy request failed"}), 500
```

## Advanced SSRF Protection

### DNS Rebinding Protection
```python
import time

class DNSRebindingProtection:
    def __init__(self):
        self.dns_cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    def resolve_and_validate(self, hostname):
        """Resolve hostname and validate against DNS rebinding"""
        cache_key = hostname
        current_time = time.time()
        
        # Check cache
        if cache_key in self.dns_cache:
            cached_data = self.dns_cache[cache_key]
            if current_time - cached_data['timestamp'] < self.cache_ttl:
                return cached_data['ips']
        
        # Resolve hostname
        try:
            ip_addresses = socket.getaddrinfo(hostname, None)
            resolved_ips = [ip[4][0] for ip in ip_addresses]
            
            # Validate all resolved IPs
            for ip_str in resolved_ips:
                ip = ipaddress.ip_address(ip_str)
                for network in ssrf_protection.blocked_networks:
                    if ip in network:
                        raise SSRFError(f"DNS rebinding attempt detected: {hostname} -> {ip}")
            
            # Cache the result
            self.dns_cache[cache_key] = {
                'ips': resolved_ips,
                'timestamp': current_time
            }
            
            return resolved_ips
            
        except socket.gaierror as e:
            raise SSRFError(f"DNS resolution failed: {str(e)}")
```

### Request Rate Limiting
```python
from collections import defaultdict
import time

class SSRFRateLimiter:
    def __init__(self):
        self.request_counts = defaultdict(list)
        self.max_requests = 10  # per minute
        self.window_size = 60   # seconds
    
    def check_rate_limit(self, user_id):
        """Check if user has exceeded SSRF request rate limit"""
        current_time = time.time()
        user_requests = self.request_counts[user_id]
        
        # Remove old requests outside the window
        user_requests[:] = [req_time for req_time in user_requests 
                           if current_time - req_time < self.window_size]
        
        # Check if limit exceeded
        if len(user_requests) >= self.max_requests:
            raise SSRFError("Rate limit exceeded for external requests")
        
        # Record this request
        user_requests.append(current_time)
```

## Prevention Strategies

1. **Input Validation**: Validate and sanitize all URLs
2. **Whitelist Approach**: Only allow requests to approved domains
3. **Network Segmentation**: Isolate application servers from internal networks
4. **DNS Protection**: Implement DNS rebinding protection
5. **Rate Limiting**: Limit external request frequency per user
6. **Monitoring**: Log and monitor all external requests
7. **Principle of Least Privilege**: Minimize network access from application servers

## Testing for SSRF

```bash
# Test basic SSRF
curl "http://localhost:5001/fetch?url=http://localhost:8080/admin"

# Test cloud metadata access
curl "http://localhost:5001/fetch?url=http://169.254.169.254/latest/meta-data/"

# Test internal network scanning
curl "http://localhost:5001/fetch?url=http://192.168.1.1:22"

# Test file system access
curl "http://localhost:5001/fetch?url=file:///etc/passwd"
```

## References
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Guide](https://portswigger.net/web-security/ssrf)
- [SSRF Bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM)

---
**⚠️ WARNING: The code in this directory contains intentional security vulnerabilities for educational purposes. Never use these patterns in production systems!**
