from flask import Flask, request, jsonify, redirect
import os
import hashlib
import random

app = Flask(__name__)

secret = os.environ.get('FLAG')
secret_user = os.environ.get('NITE_USER')
secret_password = os.environ.get('NITE_PASSWORD')

def generate_filename():
    pid = os.getpid()
    uid = os.getuid()
    gid = os.getgid()
    
    seed = int(f"{pid}{uid}{gid}")
    random.seed(seed)
    
    random_num = random.randint(100000, 999999)
    hash_part = hashlib.sha256(str(random_num).encode()).hexdigest()[:16]
    
    return f"{hash_part}.txt"

name = generate_filename()
secret_DIR = '/app/nite-vault/secrets'
secret_PATH = os.path.join(secret_DIR, name)

os.makedirs(secret_DIR, exist_ok=True)

with open(secret_PATH, 'w') as f:
    f.write(secret)

PUBLIC_DIR = '/app/nite-vault/files'

def check_auth():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if username == secret_user and password == secret_password:
        return True
    
    return False

@app.route('/')
def index():
    return redirect('/view')

@app.route('/view')
def view_file():
    if not check_auth():
        return jsonify({
            'error': 'Authentication required',
            'message': 'Please provide valid credentials'
        }), 401
    
    filename = request.args.get('file', request.args.get('filename', 'file1.txt'))
    
    if '../' in filename or '..\\'in filename:
        return 'Path traversal detected', 403
    
    try:
        if not filename.startswith('/'):
            file_path = os.path.join(PUBLIC_DIR, filename)
        else:
            file_path = filename
        
        if os.path.isfile(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            return content
        else:
            return 'File not found', 404
    except Exception as e:
        return f'Error: {str(e)}', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)