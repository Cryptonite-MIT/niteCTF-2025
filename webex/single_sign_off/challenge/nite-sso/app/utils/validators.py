import re

def validate_username(username):
    if not username:
        return False
    
    if len(username) < 3 or len(username) > 20:
        return False

    if not username[0].isalpha():
        return False
    
    pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*$')
    return bool(pattern.match(username))

def validate_password(password):
    if not password:
        return False
    
    if len(password) < 6:
        return False
    
    return True

def validate_session_id(session_id):
    if not session_id:
        return False
    
    pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)
    return bool(pattern.match(session_id))

def sanitize_input(text, max_length=255):
    if not text:
        return ""

    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length]

    dangerous_chars = ['<', '>', '"', "'", '&', ';']
    for char in dangerous_chars:
        text = text.replace(char, '')
    
    return text
