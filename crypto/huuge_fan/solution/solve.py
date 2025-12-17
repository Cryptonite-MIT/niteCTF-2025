from sage.all import *
import ast, pathlib
from tqdm import tqdm
from multiprocessing import Pool
from hashlib import sha256
from pprint import pformat
from typing import Optional


def solve_xi(n: int):
    '''
    n = [
        (t**8 + 1)*     a*e,
        (t**7 + t)*     (a*d + b*e),
        (t**6 + t**2)*  (a*c + b*d + c*e),
        (t**5 + t**3)*  (a*b + b*c + c*d + d*e),
        (t**4)*         (a**2 + b**2 + c**2 + d**2 + e**2)
    ]
    '''
    M = [[
        base**8 + 1,
        base**7 + base**1,
        base**6 + base**2,
        base**5 + base**3,
        base**4
    ]]
    b = [n]
    lb = [0]*5
    ub = [
        1*base**N_NUMS,
        2*base**N_NUMS,
        3*base**N_NUMS,
        4*base**N_NUMS,
        5*base**N_NUMS
    ]

    load('https://raw.githubusercontent.com/TheBlupper/linineq/main/linineq.py')
    sols_xyz = solve_bounded_gen(matrix(M), b, lb, ub, solver='ppl')

    return sols_xyz

def solve_ai(partial: tuple[int]) -> Optional[list[int]]:
    R = PolynomialRing(QQ, 'a,b,c,d,e')
    parts = R.gens()
    a, b, c, d, e = parts
    eqns = [
        (a*e),
        (a*d + b*e),
        (a*c + b*d + c*e),
        (a*b + b*c + c*d + d*e),
        (a**2 + b**2 + c**2 + d**2 + e**2)
    ]
    Fi = [eqns[i] - partial[i] for i in range(len(eqns))]
    I = ideal(*Fi)
    G = I.groebner_basis(algorithm='msolve', proof=False)
    sols = I.variety() # returns dicts with a,b,c,d,e over QQ
    # print(f"{len(sols)} solutions for ai") # usually 3
    if sols:
        return [int(sols[0][i]) for i in parts]
    else:
        return None

def solve_msb(n: int):
    sols_xi = solve_xi(n)
    pbar = tqdm(sols_xi, leave = False)
    for xi in pbar:
        ai = solve_ai(xi)
        if ai:
            print(f"{n} = x{ai}")
            return sorted(ai)
    else:
        raise ValueError("Did not find correct xi_s")

def hashmsg(msg: bytes):
    global ring
    return ring(int.from_bytes(sha256(msg).digest()))

def solve_flag(signs):
    '''
    signs: list[tuple[known MSB, r, s, z]]
    '''
    global TOTAL, MOD, base
    l = base.bit_length()

    ai = lambda k, r, s, z: r / s
    bi = lambda k, r, s, z: (z / s) - k
    A = [ai(*i) for i in signs]
    B = [bi(*i) for i in signs]

    M = matrix(QQ,
        (identity_matrix(TOTAL)*MOD)
        .augment(vector(A))
        .augment(vector(B))
        .stack(vector([0]*TOTAL + [Integer(1)/2**l, 0]))
        .stack(vector([0]*TOTAL + [0, Integer(MOD)/2**l]))
    ).T
    M = M.LLL()
    for r in M:
        if r[-1] == Integer(MOD)/2**l:
            d_rec = ring(r[-2]*2**l)
            break

    print(f"Recovered priv key `d`: {d_rec.to_bytes()}") # Flag
    # print((-d_rec).to_bytes()) # Use if necessary


if __name__ == "__main__":
    with open(pathlib.Path(__file__).parents[1] / "challenge" / "public" / "out.txt") as f:
        inp: list[tuple[int, list[tuple[str, int, int]]]] = ast.literal_eval(f.read().strip())

    TOTAL = 60 # total signatures
    NUM_PARTS = TOTAL // len(inp) # number of parts in each number (5)
    NUM_DIGITS = 4 # number of MSdigits leaked
    N_NUMS = 2 # number of numbers
    MOD = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
    ring = Zmod(MOD)
    base = int(str(MOD)[:NUM_DIGITS]) # each leak is less than this number

    with Pool() as pool:
        known_msbs = pool.map(solve_msb, (i[0] for i in inp))

    print(f"Recovered MSB of nonces: {pformat(known_msbs)}")
    signs = list() # known, r, s, z
    for batch in range(len(inp)):
        for i in range(NUM_PARTS):
            leak = known_msbs[batch][i] * 10**(len(str(MOD)) - NUM_DIGITS)
            msg, r, s = inp[batch][1][i]
            r, s = ring(r), ring(s)
            z = hashmsg(bytes.fromhex(msg))
            signs.append((leak, r, s, z))
    solve_flag(signs)
