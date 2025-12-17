from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
from pwn import xor
from z3 import *
import re

ROUNDS = 128
ct, leak = open("out.txt").read().splitlines()[:2]
ct = bytes.fromhex(ct)
bits = [int(b) for b in f"{int(leak,16):0{ROUNDS}b}"]
N = 3

s = Solver()
key_bytes = [BitVec(f'k_{i}', 8) for i in range(16)]
nonce = key = Concat(*key_bytes)
curr = 0

for i in range(ROUNDS):
    bit = bits[i]
    curr = (curr << 1) | bit
    s.add(Extract(127, 127, nonce) == bit)
    nonce += curr
    nonce = RotateLeft(nonce, N)

if s.check() == sat:
    m = s.model()
    recovered_key = bytearray()
    for b in key_bytes: recovered_key.append(m[b].as_long())
    print(f"key bytes: {recovered_key}")
    print(f"key hex: {recovered_key.hex()}")
else:
    print("couldn't find a key")

def rol(num, n):
    return ((num << n) | (num >> (128-n))) % (256 ** 16)

def keystream(KEY):
    CIPHER = AES.new(KEY, AES.MODE_ECB)
    leak = ""
    nonce = bytes_to_long(KEY)
    while True:
        leak += f"{nonce >> 127:b}"
        nonce = (nonce + int(leak, 2)) % (256 ** 16)
        yield CIPHER.encrypt(nonce.to_bytes(16))
        nonce = rol(nonce, N)

def decrypt(ciphertext: bytes, key: bytes):
    assert len(ciphertext) % 16 == 0
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    ks = keystream(key)
    pt = b''
    for c in blocks:
        pt += xor(c, next(ks))
    return pt

pt = decrypt(ct, recovered_key)
flag = re.search(rb'nite\{.*?\}', pt)
if flag:
    print(f"flag: {flag.group().decode()}")