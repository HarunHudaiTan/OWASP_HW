"""
A08: Software and Data Integrity Failures Example
OWASP Top 10 2021

Simple example of data integrity failures.
DO NOT use in production!
"""

from flask import Flask, request, jsonify
import requests
import pickle
import base64

app = Flask(__name__)

@app.route('/download_update', methods=['POST'])
def download_update():
    """Download software update without integrity verification."""
    update_url = request.json['url']
    
    # Download without verifying source or integrity
    response = requests.get(update_url)
    
    with open('update.zip', 'wb') as f:
        f.write(response.content)
    
    return jsonify({"message": "Update downloaded successfully"})

@app.route('/load_data', methods=['POST'])
def load_data():
    """Load serialized data without verification."""
    data = request.json['data']
    
    # Deserialize data without integrity check - dangerous!
    try:
        decoded_data = base64.b64decode(data)
        loaded_data = pickle.loads(decoded_data)  # Unsafe deserialization
        return jsonify({"result": str(loaded_data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/auto_update')
def auto_update():
    """Auto-update feature without signature verification."""
    # Fetch update from untrusted source
    update_server = "http://updates.example.com/latest"
    
    try:
        response = requests.get(update_server)
        update_info = response.json()
        
        # Apply update without verifying signature or checksum
        return jsonify({
            "message": "Auto-update completed",
            "version": update_info.get('version', 'unknown')
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Secure Data Integrity Solutions
import hashlib
import hmac
import json

# Secret key for HMAC (in production, use environment variable)
INTEGRITY_KEY = b'secure_integrity_key_change_in_production'

@app.route('/secure/download_update', methods=['POST'])
def secure_download_update():
    """
    Secure software update download with integrity verification.
    """
    data = request.get_json()
    update_url = data.get('url')
    expected_hash = data.get('sha256_hash')
    signature = data.get('signature')
    
    if not all([update_url, expected_hash, signature]):
        return jsonify({"error": "URL, hash, and signature required"}), 400
    
    # Validate URL
    if not update_url.startswith('https://trusted-updates.example.com/'):
        return jsonify({"error": "Untrusted update source"}), 400
    
    try:
        # Download with SSL verification
        response = requests.get(update_url, verify=True, timeout=30)
        response.raise_for_status()
        
        # Verify file integrity
        file_hash = hashlib.sha256(response.content).hexdigest()
        if file_hash != expected_hash:
            return jsonify({"error": "File integrity check failed"}), 400
        
        # Verify signature (simplified - use proper crypto library in production)
        expected_signature = hmac.new(
            INTEGRITY_KEY, 
            response.content, 
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return jsonify({"error": "Signature verification failed"}), 400
        
        # Save verified update
        with open('verified_update.zip', 'wb') as f:
            f.write(response.content)
        
        return jsonify({
            "message": "Update downloaded and verified successfully",
            "hash": file_hash
        })
        
    except Exception as e:
        return jsonify({"error": "Update download failed"}), 500

@app.route('/secure/load_data', methods=['POST'])
def secure_load_data():
    """
    Secure data loading with integrity verification and safe deserialization.
    """
    data = request.get_json()
    
    if 'data' not in data or 'signature' not in data:
        return jsonify({"error": "Data and signature required"}), 400
    
    try:
        # Decode data
        encoded_data = data['data']
        provided_signature = data['signature']
        
        # Verify signature before deserializing
        expected_signature = hmac.new(
            INTEGRITY_KEY,
            encoded_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(provided_signature, expected_signature):
            return jsonify({"error": "Data integrity check failed"}), 400
        
        # Use safe JSON instead of pickle
        decoded_data = base64.b64decode(encoded_data)
        loaded_data = json.loads(decoded_data.decode('utf-8'))
        
        return jsonify({
            "result": loaded_data,
            "message": "Data loaded securely"
        })
        
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON data"}), 400
    except Exception as e:
        return jsonify({"error": "Data processing failed"}), 400

@app.route('/secure/create_signed_data', methods=['POST'])
def create_signed_data():
    """
    Helper endpoint to create properly signed data for testing.
    """
    input_data = request.get_json()
    
    # Serialize data as JSON (safer than pickle)
    json_data = json.dumps(input_data)
    encoded_data = base64.b64encode(json_data.encode()).decode()
    
    # Create signature
    signature = hmac.new(
        INTEGRITY_KEY,
        encoded_data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return jsonify({
        "data": encoded_data,
        "signature": signature,
        "message": "Use this signed data with /secure/load_data"
    })

if __name__ == '__main__':
    print("Vulnerable endpoints: /download_update, /load_data, /auto_update")
    print("Secure endpoints: /secure/download_update, /secure/load_data, /secure/create_signed_data")
    
    app.run(debug=True, port=5002)
