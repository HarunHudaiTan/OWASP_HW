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

if __name__ == '__main__':
    app.run(debug=True, port=5002)
