import subprocess
import os
from flask import Flask, request, jsonify, redirect, make_response, render_template_string

app = Flask(__name__)

# Internal communication uses localhost
SSO_INTERNAL = 'http://127.0.0.1:8989'

DOMAIN = os.environ.get('DOMAIN', 'localhost')
SSO_EXTERNAL = os.environ.get('SSO_EXTERNAL_URL', f'http://nite-sso.{DOMAIN}')
PORTAL_EXTERNAL = os.environ.get('PORTAL_EXTERNAL_URL', f'http://document-portal.{DOMAIN}')

def validate_sso_session(session_id):
    import requests
    try:
        response = requests.get(
            f'{SSO_INTERNAL}/app/logincheck',
            params={'sessionId': session_id},
            timeout=5
        )
        data = response.json()
        return data.get('code') == 200
    except:
        return False

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Document Portal</title>
</head>
<body>
    <h1>nite Document Portal</h1>
    <p>Internal document fetcher service</p>
    
    <form onsubmit="fetchUrl(); return false;">
        <input type="text" id="url" placeholder="Enter URL" size="60" required>
        <button type="submit">Fetch</button>
    </form>
    
    <pre id="result"></pre>
    
    <script>
        function fetchUrl() {
            const url = document.getElementById('url').value;
            document.getElementById('result').textContent = 'Fetching...';
            
            fetch('/fetch', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result').textContent = data.response || 'No response';
            })
            .catch(err => {
                document.getElementById('result').textContent = 'Error: ' + err;
            });
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    session_id = request.cookies.get('nite_sso_sessionid')
    
    if not session_id:
        return f"Please log in to SSO first: <a href='{SSO_EXTERNAL}/login?redirect_url={PORTAL_EXTERNAL}/sso-callback'>Click here to login</a>"
    
    if not validate_sso_session(session_id):
        response = make_response(f"Session expired. Please <a href='{SSO_EXTERNAL}/login?redirect_url={PORTAL_EXTERNAL}/sso-callback'>log in again</a>")
        response.set_cookie('nite_sso_sessionid', '', expires=0, path='/')
        return response
    
    return render_template_string(HTML)

@app.route('/sso-callback')
def sso_callback():
    session_id = request.args.get('sessionId')
    
    if not session_id:
        return "Error: No session ID provided", 400
    
    response = make_response(redirect('/'))
    response.set_cookie('nite_sso_sessionid', session_id, httponly=True, samesite='Lax', path='/')
    return response

@app.route('/logout')
def logout():
    response = make_response(redirect('/'))
    response.set_cookie('nite_sso_sessionid', '', expires=0, path='/')
    return response

@app.route('/fetch', methods=['POST'])
def fetch():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'response': 'error', 'success': False})

    if 'nite-vault' in url.lower():
        return jsonify({'response': 'Security Error: Access to nite-vault is restricted', 'success': False})
    
    try:
        result = subprocess.run(
            ['./fetcher', url],
            capture_output=True,
            text=True,
            timeout=15
        )
        output = result.stdout
        if result.stderr:
            output += '\n' + result.stderr # output += '\n--- Errors ---\n' + result.stderr
        return jsonify({'response': output, 'success': True})
    except subprocess.TimeoutExpired:
        return jsonify({'response': 'Timeout: Request took too long', 'success': False})
    except Exception as e:
        return jsonify({'response': f'Error: {str(e)}', 'success': False})

if __name__ == '__main__':

    app.run(host='0.0.0.0', port=10000)
