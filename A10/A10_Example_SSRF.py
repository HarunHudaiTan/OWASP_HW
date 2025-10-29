"""
A10: Server-Side Request Forgery (SSRF) Example
OWASP Top 10 2021

Simple example of SSRF vulnerability.
DO NOT use in production!
"""

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

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

@app.route('/proxy')
def proxy():
    """Simple proxy service."""
    target = request.args.get('target')
    
    # Proxy request without URL validation
    response = requests.get(target)
    return response.content, response.status_code

# Secure SSRF Prevention Solutions
import urllib.parse
import ipaddress

def is_safe_url(url):
    """Validate URL to prevent SSRF attacks."""
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Only allow HTTPS
        if parsed.scheme != 'https':
            return False, "Only HTTPS URLs allowed"
        
        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            # Block private/local IP ranges
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, "Private IP addresses not allowed"
        except ValueError:
            # It's a hostname, not an IP
            pass
        
        # Whitelist allowed domains
        allowed_domains = [
            'api.example.com',
            'secure.example.org',
            'trusted-service.com'
        ]
        
        if parsed.hostname not in allowed_domains:
            return False, "Domain not in whitelist"
        
        return True, "URL is safe"
        
    except Exception:
        return False, "Invalid URL format"

@app.route('/secure/fetch', methods=['GET'])
def secure_fetch_url():
    """Secure URL fetching with SSRF protection."""
    url = request.args.get('url')
    
    if not url:
        return jsonify({"error": "URL parameter required"}), 400
    
    # Validate URL
    is_safe, message = is_safe_url(url)
    if not is_safe:
        return jsonify({"error": f"URL validation failed: {message}"}), 400
    
    try:
        # Fetch with additional security measures
        response = requests.get(
            url, 
            timeout=5,  # Short timeout
            allow_redirects=False,  # Prevent redirect-based SSRF
            verify=True  # SSL verification
        )
        
        # Limit response size
        max_size = 1024 * 1024  # 1MB
        if len(response.content) > max_size:
            return jsonify({"error": "Response too large"}), 413
        
        return jsonify({
            "status_code": response.status_code,
            "content": response.text[:500],  # First 500 chars
            "message": "Content fetched securely"
        })
        
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timeout"}), 408
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request failed"}), 400

@app.route('/secure/webhook', methods=['POST'])
def secure_webhook():
    """Secure webhook processing with URL validation."""
    callback_url = request.json.get('callback_url')
    data = request.json.get('data', {})
    
    if not callback_url:
        return jsonify({"error": "Callback URL required"}), 400
    
    # Validate callback URL
    is_safe, message = is_safe_url(callback_url)
    if not is_safe:
        return jsonify({"error": f"Callback URL validation failed: {message}"}), 400
    
    try:
        # Send data with security measures
        response = requests.post(
            callback_url, 
            json=data,
            timeout=10,
            allow_redirects=False,
            verify=True
        )
        
        return jsonify({
            "message": "Webhook processed securely",
            "status_code": response.status_code
        })
        
    except Exception as e:
        return jsonify({"error": "Webhook processing failed"}), 500

@app.route('/secure/proxy')
def secure_proxy():
    """Secure proxy service with strict validation."""
    target = request.args.get('target')
    
    if not target:
        return jsonify({"error": "Target parameter required"}), 400
    
    # Validate target URL
    is_safe, message = is_safe_url(target)
    if not is_safe:
        return jsonify({"error": f"Target URL validation failed: {message}"}), 400
    
    try:
        response = requests.get(
            target,
            timeout=10,
            allow_redirects=False,
            verify=True,
            stream=True
        )
        
        # Check content type
        content_type = response.headers.get('content-type', '')
        if not content_type.startswith(('text/', 'application/json')):
            return jsonify({"error": "Content type not allowed"}), 400
        
        return response.content, response.status_code, {'Content-Type': content_type}
        
    except Exception as e:
        return jsonify({"error": "Proxy request failed"}), 500

if __name__ == '__main__':
    print("Vulnerable endpoints: /fetch, /webhook, /proxy")
    print("Secure endpoints: /secure/fetch, /secure/webhook, /secure/proxy")
    
    app.run(debug=True, port=5002)
