from flask import Flask, request, Response, jsonify
import os
import time
import logging
import uuid
import threading
import json


app = Flask(__name__)


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


FLAG = os.environ.get('FLAG', 'nite{h11p_1_1_must_d1e}')


player_sessions = {}
session_lock = threading.Lock()


def cleanup_old_sessions():
    while True:
        time.sleep(60)
        with session_lock:
            current_time = time.time()
            for user_id in list(player_sessions.keys()):
                sessions = player_sessions[user_id]
                for token in list(sessions.keys()):
                    if current_time - sessions[token]['timestamp'] > 3600:
                        del sessions[token]
                if not sessions:
                    del player_sessions[user_id]


cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
cleanup_thread.start()


def get_user_id():
    user_id = request.cookies.get('user_id')
    if not user_id:
        user_id = str(uuid.uuid4())
    return user_id


def create_session_token(user_id):
    
    token = str(uuid.uuid4())
    with session_lock:
        if user_id not in player_sessions:
            player_sessions[user_id] = {}
        player_sessions[user_id][token] = {
            'poisoned': False,
            'timestamp': time.time(),
            'user_id': user_id
        }
    
    return token



def check_session_poisoned(token, user_id):
    if not token or not user_id:
        return False

    with session_lock:
        if user_id not in player_sessions:
            return False

        sessions = player_sessions[user_id]
        if token not in sessions:
            return False

        session = sessions[token]

        if time.time() - session['timestamp'] > 3600:
            del sessions[token]
            return False

        if session.get('user_id') != user_id:
            return False

        return session.get('poisoned', False)


def get_forwarded_for_variants():
    
    return request.headers.get('X-Forwarded-For')


def is_admin_ip(ip):
    if not ip:
        return False
    ip = str(ip).strip()
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    return (ip.startswith('127.') or ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.'))


@app.route('/')
def index():
    user_id = get_user_id()

    html = f'''<!DOCTYPE html>
<html>
<head>
    <title>NiteProxy</title>
    <style>
        body {{ background: #0a0a0a; color: #ccc; font-family: monospace; padding: 2rem; }}
        .container {{ max-width: 800px; margin: 0 auto; border: 1px solid #333; padding: 1rem; }}
        h1 {{ color: #fff; border-bottom: 1px solid #333; padding-bottom: 0.5rem; margin-bottom: 1rem; font-size: 1.2rem; }}
        .stat {{ margin-bottom: 0.5rem; }}
        .label {{ color: #666; width: 120px; display: inline-block; }}
        .value {{ color: #0f0; }}
        .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #444; border-top: 1px solid #333; padding-top: 1rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>NiteProxy: </h1>
        <div class="stat"><span class="label">Status:</span> <span class="value">ONLINE</span></div>
        <div class="stat"><span class="label">Upstream:</span> <span class="value">CONNECTED</span></div>
        <div class="stat"><span class="label">Client ID:</span> {user_id}</div>

        <div class="footer">
            Authorized Access Only
        </div>
    </div>
</body>
</html>'''

    response = Response(html, mimetype='text/html')
    response.set_cookie('user_id', user_id, max_age=86400, httponly=True, samesite='Lax')
    return response


@app.route('/health')
def health():
    return jsonify({"status": "ok", "timestamp": int(time.time())}), 200


@app.route('/con', methods=['GET', 'POST'])
def reserved_names():
    user_id = get_user_id()
    token = create_session_token(user_id)   

    content_length = request.headers.get('Content-Length')
    if content_length:
        try:
            if int(content_length) > 0:
                with session_lock:
                   
                    player_sessions[user_id][token]['poisoned'] = True
        except Exception:
            pass

    response = Response("Reserved", status=200, headers={'Connection': 'keep-alive'})

    cookie_kwargs = {
        "max_age": 86400,
        "httponly": True,
        "samesite": "Lax",
    }
   
    if request.is_secure or os.environ.get("FORCE_SECURE_COOKIES", "0") == "1":
        cookie_kwargs["secure"] = True

    response.set_cookie('user_id', user_id, **cookie_kwargs)
    
    
    if content_length:
        try:
            if int(content_length) > 0:
                response.set_cookie('session_token', token, **cookie_kwargs)
        except Exception:
            pass
    
    return response



@app.route('/api/v1/debug')
def api_debug():
    user_id = get_user_id()
    headers_dict = dict(request.headers)

    proxy_modified_headers = []
    for h in ['X-Haproxy-Version', 'X-Proxy-Instance', 'X-Apache-Layer', 'X-Backend-Route']:
        if h in headers_dict:
            proxy_modified_headers.append(h)

    return jsonify({
        'request_id': str(uuid.uuid4()),
        'timestamp': int(time.time()),
        'user_id': user_id,
        'method': request.method,
        'path': request.path,
        'remote_addr': request.remote_addr,
        'proxy_chain': {
            'layers_traversed': len(proxy_modified_headers) // 2 if proxy_modified_headers else 0,
        },
        'headers': headers_dict
    })


@app.route('/api/v1/session/check')
def api_session_check():
    """Check current session state - helps verify if session poisoning worked"""
    user_id = get_user_id()
    session_token = request.cookies.get('session_token')

   
    is_poisoned = check_session_poisoned(session_token, user_id)

   
    session_exists = False
    session_info = None

    if session_token and user_id:
        with session_lock:
            if user_id in player_sessions and session_token in player_sessions[user_id]:
                session_exists = True
                session_info = {
                    'created': player_sessions[user_id][session_token]['timestamp'],
                    'age_seconds': int(time.time() - player_sessions[user_id][session_token]['timestamp'])
                }

    response_data = {
        'request_id': str(uuid.uuid4()),
        'timestamp': int(time.time()),
        'user_id': user_id,
        'session_token': session_token[:8] + '...' if session_token else None,
        'session_exists': session_exists,
        'session_state': 'poisoned' if is_poisoned else ('clean' if session_exists else 'no_session'),
        'admin_accessible': is_poisoned,
    }

    if session_info:
        response_data['session_info'] = session_info

    return jsonify(response_data), 200


@app.route('/api/v1/data', methods=['GET', 'POST'])
def api_data():
    user_id = get_user_id()

    try:
        body = request.get_data(as_text=True)

        if body and '\r\n\r\n' in body:
            lines = body.split('\r\n')
            if lines and lines[0].startswith(('GET ', 'POST ')):
                smuggled_method, smuggled_path = lines[0].split(' ')[:2]

                smuggled_headers = {}
                for line in lines[1:]:
                    if not line:
                        break
                    if ':' in line:
                        key, val = line.split(':', 1)
                        smuggled_headers[key.strip()] = val.strip()

                if '/admin' in smuggled_path:
                    
                    smuggled_ip = smuggled_headers.get('X-Forwarded-For')
                    offset_header = smuggled_headers.get('X-Offset')

                   
                    suspicious_headers = [
                        'A-Forwarded-For', 'Forwarded-For-Bypass', 'X-Custom-Forwarded-For',
                        'For-Forwarded', 'A-For-Forwarded', 'X-Forwarded-For-Original',
                        'Forwarded-For', 'X-Real-IP', 'X-Client-IP', 'Client-IP',
                        'X-Original-Forwarded-For', 'Forwarded', 'True-Client-IP'
                    ]
                    
                    
                    for sus_header in suspicious_headers:
                        if sus_header in smuggled_headers:
                            return jsonify({"status": "ok", "processed": False, "timestamp": int(time.time())}), 200
                    
                    
                    if not smuggled_ip:
                        return jsonify({"status": "ok", "processed": False, "timestamp": int(time.time())}), 200

                    if not offset_header:
                        return jsonify({"status": "ok", "processed": False, "timestamp": int(time.time())}), 200

                    injected_headers_list = ['X-Haproxy-Version', 'X-Proxy-Instance', 'X-Apache-Layer', 'X-Backend-Route']
                    actual_injected_bytes = sum(len(f"{h}: {request.headers.get(h)}\r\n") for h in injected_headers_list if request.headers.get(h))

                    try:
                        calculated_bytes = int(offset_header)
                        if abs(calculated_bytes - actual_injected_bytes) > 5:
                            return jsonify({"status": "ok", "processed": False, "timestamp": int(time.time())}), 200
                    except:
                        return jsonify({"status": "ok", "processed": False, "timestamp": int(time.time())}), 200

                    if smuggled_ip and is_admin_ip(smuggled_ip):
                        cookie_header = smuggled_headers.get('Cookie', '')
                        session_token = None
                        smuggled_user_id = None

                        for part in cookie_header.split(';'):
                            part = part.strip()
                            if 'session_token=' in part:
                                session_token = part.split('=')[1]
                            elif 'user_id=' in part:
                                smuggled_user_id = part.split('=')[1]

                        if check_session_poisoned(session_token, smuggled_user_id):
                            return jsonify({
                                "status": "ok", 
                                "flag": FLAG, 
                                "message": "Access granted",
                                "timestamp": int(time.time())
                            }), 200
    except:
        pass

    return jsonify({"status": "ok", "processed": False, "timestamp": int(time.time())}), 200



@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
