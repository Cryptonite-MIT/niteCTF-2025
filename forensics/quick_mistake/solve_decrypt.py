import json
import binascii
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys

SEED_HEX = "af717e2c8789db71fe624598faba3953c23fdb685e6b8cd2e6f84beef0c57175"
SALT = b"telemetry"
INFO = b"sslkeylog"

CHUNKS = [
    {
        "type": "telemetry_sslkeylog",
        "seq": 0,
        "total_chunks": 2,
        "nonce_b64": "S459VmTWtpNcz+NU",
        "ct_b64": "D4Y706RkRpgzXAOAWe4eKyE3AjfFXxOgxXGV7SsKeH4umYbfaY6VMedKeghapSgIyghK7rLSJxwRWwDREt1sN+ZV3MPnw4CdaqOWdh3o3dLtlyJSsDg9iYYAynV68VaXKQna5xFGaFr9x0b3vuvbFTJ7u3zgTlAmpEutj0F4leuLZDGRZupvr9+jyNLxnGNVxNXwLTcYSIR1iTOUdao/252x4H9c7DjCeuvCDX4hYfPv+l5g8JEuwutqCbdzn3nVkL4s0931lT8wpkV4suIR+0bV+X4SU8pd6XlrkxweEWpVIbJkhqnKh5driyqA/1TneBVZKS03k7TiX9ZXqmVhS4r3BKrk7wMnVwQLSLmC07UOvIEsqzWp0GJnYvyGV1FzB7Tw4JXakoLhOGs+ocpGr2PuhSrUTiAW465ikw3+lsEnKI/OFG7I+2nVjKkBA09bu17iJHNoOD3rmQ0cRGiJ8/Vr3YufXeQDMn/REyoG+Wnv/P5rR1I/O6qn/5LHiWSqaNWpg7jjRvU/pt4KBPMMTckeXTseYUwts0Ntk7IBBztYnmq1zZSNhdAZ+KQQ1/8I/lJVdgg5YWZSdepexZVJuiofPgYN55fnvWqK/LxmVE4D3gOKKbJWCQoL1FgadmZ4iX99MjYzs2qsOp9m8i1yvrMbQ4emX7hjjk74I5rfZ9E+01bBvLiw4smdlBiT4ztWA/uQPYqZC/kN06Fu9LTYTCGR8/B/4mAlKUh6ZzQDePGrYiuR0k5/WRH2fzcYnUAt5NOt6akHE3ljXOW28PV2G5IL94IxPYkITHNPTMp2J84QcuozCHtf9ex/b3fG+DLPXT0zrxh5j11SsCTULPUmLXKKqCXc/NHaxHrquM7PUZi5fQZ7Jmz386K+2ExR4ycTNVSB2MuPDzvG+FPQP60M6varPywdWM6lM7IrDQ02lXC7/n9o+m60uIjfI52IvDe4b2NFJQeU2dFPKkAX1N68yWGc75IVz2noScPqaq4P978sT+z9DfKOe0ifQc0So8qoi2WHKvB5bEUjFezszGhWzq7rJ7toUu5rg+t5i9Tuf/qpFZfcwBHyPr8o6bmkLj0p9IsEldTKUZiD4Ng8ReYn9pwwc6weeZ02D432ziDSxwIB5NA/32GV50hT+4EvTeo1cCyyGxT9Na+Qd3RVoJgO4TDWTLYwVI/x2cFa88WbAjMHveWGGiEK5TZD3Ad2Jkj3UmTj0ETTuzW1aTqTHEfVY+7A/XTNN3E1Q4VB2+e+p2JxybXgvYSmhX0aQuzmqwXhRmA8BnpBBvwl/99rKQLdJUPnnrre06Om8Azi81212PaQtiq+IEuMWg==",
        "tag_b64": "ElHxGRAt7wicOe+lFkLiaw=="
    },
    {
        "type": "telemetry_sslkeylog",
        "seq": 1,
        "total_chunks": 2,
        "nonce_b64": "tXd5ku7fU1lPn/D9",
        "ct_b64": "o6vvBmgm6Iyj9/RRUjDdqtcFj6tn4E/7whY/4do67UD3NgRHqicb3eWZ+O8xvMaok+MHjhRreah9QQS1NEy+fAbDGMhqVqwqeNS6F5j+MOv7UX7N1wn2ZyaIxT2UogGb6D2c+F7rnaJZdpsrDQ/ZEwQTaJVuHGNTQM1klV+UZOUJ4mZzSp+/u8M1p/JJrDcMjzaGypiP7HrZ+g6FGkL83PCzWKGSVw/3syZtuzu65Owtk5XbYqDRn7MN1rYeuCzoYlSoQ3ZccUQkk9+U4BTfgImBlBqT3D3byVxqMuz5JR6MyK/AGkUXpn2qaBtX00rEtKhnJ7iLRkkBVeXbUd/rWqUfGpf6QpOEiVQeA17p80mw5g68X52u03388XhfIbfR/qehWE7wK/t8O90/CiTNvCrhFgNg5Kvze/zgDz0lJ2h3sCoThsUjP6m3lXV6rYFnswLr6fmvD26tU3+wrmSvdBbHfaLovLmmBtI9bjDw44vpgNQ4HxttPiPllYZXZYvhTrs7P4XDDqDGRHwiHn0AmDR79UVrVO0ie5RsQt91wMT+3OhxiScRiH+xw7RpTd6wb3SLNcNwVQSc+zm3ZLBv8cNGj6TknRhbcSkZxmK7yANX3FcorjuGJDd+5kSzzOihuEw8qXVLXI0XLHtL7wz7nWDP8bKLIYvOVRd59aRnOuuH9dCD4Zc5",
        "tag_b64": "ZlYYx1K6YiALxD0Tm9k6/w=="
    }
]

def derive_key(seed_hex, salt, info):
    seed = bytes.fromhex(seed_hex)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(seed)

def main():
    print(f"[*] Deriving key from Seed: {SEED_HEX}")
    key = derive_key(SEED_HEX, SALT, INFO)
    aesgcm = AESGCM(key)
    print(f"[*] Decrypting {len(CHUNKS)} chunks...")
    sorted_chunks = sorted(CHUNKS, key=lambda x: x['seq'])
    final_payload = b""
    for c in sorted_chunks:
        nonce = binascii.a2b_base64(c['nonce_b64'])
        ct = binascii.a2b_base64(c['ct_b64'])
        tag = binascii.a2b_base64(c['tag_b64'])
        full_ct = ct + tag
        try:
            pt = aesgcm.decrypt(nonce, full_ct, None)
            final_payload += pt
        except Exception as e:
            print(f"[-] Decryption failed for chunk {c['seq']}: {e}")
            return
    try:
        print("\n--- RECOVERED SSLKEYLOGFILE ---")
        print(final_payload.decode('utf-8'))
        print("--- END ---")
    except UnicodeDecodeError:
        print("\n--- RECOVERED BINARY DATA ---")
        print(final_payload)

if __name__ == "__main__":
    main()
