from sage.all import *
from hashlib import sha256
import os, time
from pprint import pprint
from .p1 import gen_n, solve_full, n_parts

F = GF(2**448 - 2**224 - 1)
C = EllipticCurve(F, [0, 0x262A6, 0, 1, 0])
n = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
R = Zmod(n)
G = C.lift_x(F(5))  # base point

d = R.random_element()  # private key
Q = d * G  # public key
ln = 4 # number of digits leaked
l = int(str(n)[:ln]).bit_length() # number of known MSbits
t = 60 # number of signatures
nb = n.bit_length()
MAX = (t+n_parts-1)//n_parts
# (l, t) = (20, 24), (10, 60)


def H(msg: bytes):
    return R(int.from_bytes(sha256(msg).digest()))

def sign(msg: bytes, nonce: bytes | None = None):  # nonce max 446 bits (belong to R)
    global G, R, d
    while True:
        k = nonce or R.random_element()
        r = R((k * G).x())
        if r != 0:
            break
    z = H(msg)
    s = (z + r * d) / k
    return r, s

def verify(msg: bytes, r, s) -> bool:
    global G, R, Q
    z = H(msg)
    v = R(((z / s) * G + (r / s) * Q).x())
    return v == r

def oracle(msg: bytes, give_leaks = False): # max (t+4)//5 calls
    while True:
        try:
            ki = sorted([R.random_element() for i in range(n_parts)]) # if this is not sorted they cannot find the ordering of ai_s
            leak_ai = [int(str(int(i)).rjust(135)[:ln]) for i in ki]
            break
        except ValueError:
            continue
    print(f"leak = {leak_ai}")
    n = gen_n(parts=leak_ai)
    signs = [sign(msg, i) for i in ki]
    if give_leaks: return n, signs, leak_ai
    return n, signs

def solve_signs(signs, ai, bi):
    A = [ai(*i) for i in signs]
    B = [bi(*i) for i in signs]

    M = matrix(QQ,
        (identity_matrix(t)*n)
        .augment(vector(A))
        .augment(vector(B))
        .stack(vector([0]*t + [Integer(1)/2**l, 0]))
        .stack(vector([0]*t + [0, Integer(n)/2**l]))
    ).T
    M = M.LLL()
    for r in M:
        if r[-1] == Integer(n)/2**l:
            d_rec = R(r[-2]*2**l)
            break

    print(f"Actual d:\n{hex(d)}")
    print(f"Recovered d:\n{hex(d_rec)}")
    print(hex(-d_rec))

def solve():
    batches = dict() # ni: [[ri, si, zi], [ri, si, zi], ...]
    for i in range(MAX):
        m = os.urandom(10)
        n, s = oracle(m)
        batches.update({n: [list(i) + [H(m)] for i in s]})
    signs = [] #
    for n, sign in batches.items():
        # print(n, sign)
        ai = solve_full(n)
        print(f"Got ai = {ai}")
        signs += [[ai[i]] + list(sign[i]) for i in range(n_parts)]
        # print(f"{signs = }")

    ai = lambda p, r, s, z: r / s
    bi = lambda p, r, s, z: (z / s) - (p*2**(nb-l))

    solve_signs(signs, ai, bi)

def measure_solve_signs():
    # known, r, s, z
    start = time.time()
    signs = []
    for _ in range(MAX):
        m = os.urandom(10)
        n, sigs, leaks = oracle(m, give_leaks = True)
        for i in range(5):
            signs.append([leaks[i] << (nb-l), sigs[i][0], sigs[i][1], H(m)])

    pprint(signs[0])
    ai = lambda k, r, s, z: r / s
    bi = lambda k, r, s, z: (z / s) - k

    solve_signs(signs, ai, bi)
    print(f"Completed in {time.time() - start}s")


if __name__ == "__main__":
    # solve()
    measure_solve_signs()
