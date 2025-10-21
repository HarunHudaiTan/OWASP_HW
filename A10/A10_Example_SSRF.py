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

if __name__ == '__main__':

    
    app.run(debug=True, port=5001)
