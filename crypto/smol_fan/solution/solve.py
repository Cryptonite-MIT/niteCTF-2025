from sage.all import *          
from pwn import remote
from math import gcd
import hashlib

HOST = "localhost"
PORT = 1337
NUM_SIGS = 20
BITS = 200

FLAG_MESSAGE = b"gimme_flag"

p_field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n       = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

E = EllipticCurve(GF(p_field), [0, 7])

Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G  = E(Gx, Gy)
    
assert G.order() == n

def get_pubkey(io):
    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"Qx = ")
    Qx = int(io.recvline().strip())
    io.recvuntil(b"Qy = ")
    Qy = int(io.recvline().strip())
    return Qx, Qy

def get_signature(io, msg_bytes):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Enter message as hex:", msg_bytes.hex().encode())

    io.recvuntil(b"m = ")
    m = int(io.recvline().strip())
    io.recvuntil(b"a = ")
    a = int(io.recvline().strip())
    io.recvuntil(b"b = ")
    b = int(io.recvline().strip())

    temp = pow(10,m,m)
    s = gcd(temp-b,m)
    r = m//s

    print("r =",r)
    print("s =",s)

    return r, s

def recover_d(P, ZRS, B_bits=BITS):

    B = 2**B_bits
    m = len(ZRS)

    R1 = [B, 0]
    R2 = [0, B / n]  

    for (z, r, s) in ZRS:
        inv_s = inverse_mod(s, n)
        R1.append((inv_s * z) % n)
        R2.append((inv_s * r) % n)

    R1 = matrix(QQ, 1, len(R1), R1)
    R2 = matrix(QQ, 1, len(R2), R2)

    diag = -n * identity_matrix(QQ, m)
    Z = matrix(QQ, m, 2, [0] * (m * 2))

    M = block_matrix([[R1],
                      [R2],
                      [block_matrix([[Z, diag]])]])

    L = M.LLL()

    for row in L.rows():
        row = vector(ZZ, [round(x) for x in row])

        for i in range(m):
            z, r, s = ZRS[i]
            solk = row[i + 2]  

            if abs(solk) >= B:
                continue

            for k in (solk, -solk):
                try:
                    d = (inverse_mod(r, n) * (k * s - z)) % n
                except ZeroDivisionError:
                    continue

                if d * G == P:
                    print("d =",d)
                    return d
    return None

def sign_with_d(message, d):
    z = int.from_bytes(hashlib.sha256(message).digest(), "big") % n
    while True:
        k = randint(1, n-1)
        R = k * G
        r = Integer(R[0]) % n
        if r == 0:
            continue
        k_inv = inverse_mod(k, n)
        s = (k_inv * (z + r * d)) % n
        if s == 0:
            continue
        return int(r), int(s)

def main():
    io = remote(HOST, PORT)

    Qx, Qy = get_pubkey(io)

    P = E(Qx, Qy)

    ZRS = []
    for i in range(NUM_SIGS):
        msg = f"msg_{i}".encode()
        r, s = get_signature(io, msg)
        z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % n
        ZRS.append((Integer(z), Integer(r), Integer(s)))

    d = recover_d(P, ZRS, B_bits=BITS)
    if d is None:
        io.close()
        return

    r_flag, s_flag = sign_with_d(FLAG_MESSAGE, d)

    io.sendlineafter(b"> ", b"3")
    io.recvuntil(b"Enter r:")
    io.sendline(str(r_flag).encode())
    io.recvuntil(b"Enter s:")
    io.sendline(str(s_flag).encode())

    try:
        resp = io.recvline(timeout=5)
        print("Server response:", resp.decode(errors="ignore").strip())
        while True:
            line = io.recvline(timeout=0.5)
            if not line:
                break
            print(line.decode(errors="ignore").strip())
    except EOFError:
        pass

    io.close()

if __name__ == "__main__":
    main()
