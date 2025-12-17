from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import hashlib
from itertools import count

app = FastAPI()

def derive_keystream(passphrase: bytes, salt: bytes, length: int) -> bytes:
    out = b""
    for i in count(0):
        if len(out) >= length:
            break
        hasher = hashlib.sha256()
        hasher.update(passphrase)
        hasher.update(salt)
        hasher.update(i.to_bytes(4, "big"))
        out += hasher.digest()
    return out[:length]

def xor_decrypt(ciphertext: bytes, passphrase: bytes, salt: bytes = b"") -> bytes:
    ks = derive_keystream(passphrase, salt, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks))

CORRECT_SEQ = "1891771341083729"
FLAG = f"nite{{Diehard_{CORRECT_SEQ}}}"

def verify_flag(node_sequence: str) -> str:
    if node_sequence == CORRECT_SEQ:
        return FLAG
    else:
        return "Incorrect sequence, please try again."

@app.post("/api/verify")
async def check_sequence(request: Request):
    data = await request.json()
    node_sequence = data.get('node_sequence', '')
    node_sequence = "".join(filter(str.isdigit, node_sequence))
    if not node_sequence:
        return JSONResponse({"result": "Empty input!"})
    result = verify_flag(node_sequence)
    return JSONResponse({"result": result})
