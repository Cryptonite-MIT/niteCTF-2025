from sympy.ntheory.modular import crt
import random

P = Q = R = S = None
SECRET = None

def set_primes(p, q, r, s):
    global P, Q, R, S
    P, Q, R, S = p, q, r, s

def set_secret(secret):
    global SECRET
    SECRET = secret

def ENC(m, mod=None):
    if mod is None: mod = P * Q * R * S
    return int(pow(m,2,mod))

def DEC(c, moduli=None): 
    if moduli is None: moduli = [P, Q, R, S]
    roots = [(r, (-r) % m) for m in moduli for r in [pow(c, (m + 1) // 4, m)]]
    plaintexts = [crt(moduli, [roots[j][int(bit)] for j, bit in enumerate(bin(i)[2:].zfill(4))])[0] for i in range(16)]  

    random.shuffle(plaintexts)
    assert len(plaintexts) == len(set(plaintexts))

    plaintexts = [x for i, x in enumerate(plaintexts) if (-x % (P*Q*R*S)) not in plaintexts[:i]]

    assert all([(-i % (P*Q*R*S)) not in plaintexts for i in plaintexts])
    assert len(set(plaintexts)) in (7,8)

    return int(sum(plaintexts) % (P*Q*R*S))


