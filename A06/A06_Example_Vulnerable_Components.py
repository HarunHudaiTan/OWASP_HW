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

if __name__ == '__main__':

    app.run(debug=True, port=5001)
