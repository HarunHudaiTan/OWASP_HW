"""
A06: Vulnerable and Outdated Components Example
OWASP Top 10 2021

Simple example using outdated/vulnerable components.
DO NOT use in production!
"""

# Using outdated packages with known vulnerabilities
import requests  # Assume this is an old version with vulnerabilities
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/process_xml', methods=['POST'])
def process_xml():
    """
    Process XML data using vulnerable XML parser.
    Uses default XML parser without security settings.
    """
    import xml.etree.ElementTree as ET
    
    xml_data = request.data
    
    # Vulnerable XML parsing - susceptible to XXE attacks
    try:
        root = ET.fromstring(xml_data)
        return jsonify({"message": f"Processed XML with root: {root.tag}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/download')
def download_file():
    """Download files using potentially vulnerable requests library."""
    url = request.args.get('url')
    
    # Using requests without proper SSL verification
    response = requests.get(url, verify=False)  # SSL verification disabled
    
    return response.content

# Secure Component Solutions
@app.route('/secure/process_xml', methods=['POST'])
def secure_process_xml():
    """
    Secure XML processing with defusedxml library.
    """
    try:
        # Use defusedxml to prevent XXE attacks
        from defusedxml import ElementTree as ET
        
        xml_data = request.data
        
        # Secure XML parsing
        root = ET.fromstring(xml_data)
        return jsonify({"message": f"Securely processed XML with root: {root.tag}"})
        
    except ImportError:
        return jsonify({"error": "defusedxml library not installed"}), 500
    except Exception as e:
        return jsonify({"error": "Invalid XML format"}), 400

@app.route('/secure/download')
def secure_download_file():
    """
    Secure file download with proper SSL verification and URL validation.
    """
    url = request.args.get('url')
    
    if not url:
        return jsonify({"error": "URL parameter required"}), 400
    
    # Validate URL format and allowed domains
    import urllib.parse
    parsed_url = urllib.parse.urlparse(url)
    
    if parsed_url.scheme not in ['https']:
        return jsonify({"error": "Only HTTPS URLs allowed"}), 400
    
    allowed_domains = ['api.example.com', 'secure.example.org']
    if parsed_url.netloc not in allowed_domains:
        return jsonify({"error": "Domain not allowed"}), 400
    
    try:
        # Use requests with proper SSL verification and timeout
        response = requests.get(
            url, 
            verify=True,  # SSL verification enabled
            timeout=10,   # Prevent hanging requests
            stream=True   # Stream large files
        )
        response.raise_for_status()
        
        # Limit file size
        max_size = 10 * 1024 * 1024  # 10MB
        if int(response.headers.get('content-length', 0)) > max_size:
            return jsonify({"error": "File too large"}), 413
        
        return response.content
        
    except requests.exceptions.SSLError:
        return jsonify({"error": "SSL verification failed"}), 400
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timeout"}), 408
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Download failed"}), 400

@app.route('/secure/check_dependencies')
def check_dependencies():
    """
    Check for known vulnerabilities in dependencies.
    """
    # In a real application, integrate with tools like:
    # - pip-audit
    # - safety
    # - Snyk
    # - OWASP Dependency Check
    
    return jsonify({
        "message": "Dependency security check completed",
        "recommendations": [
            "Use pip-audit to check for known vulnerabilities",
            "Keep dependencies updated regularly",
            "Use virtual environments",
            "Pin dependency versions in requirements.txt"
        ]
    })

if __name__ == '__main__':
    print("Vulnerable endpoints: /process_xml, /download")
    print("Secure endpoints: /secure/process_xml, /secure/download, /secure/check_dependencies")
    
    app.run(debug=True, port=5002)
