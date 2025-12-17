from sage.all import *
from pprint import pprint
from typing import Iterable, Literal, Generator
from tqdm import tqdm


def rotate(ele):
    V = ele.parent()
    ele = list(ele)
    ele.append(ele.pop(0))
    return V(ele)

def flip(ele):
    V = ele.parent()
    ele = list(ele)[::-1]
    return V(ele)

def to_integer(vec, be: bool=True): ## Little-endian (first element is Least Significant Digit)
    if len(vec) == 0:
        return Integer(0)

    # Derive base from the parent ring of any digit (e.g., first one)
    base = vec[0].parent().cardinality()

    num = Integer(0)
    for i in range(len(vec)):
        num += Integer((vec[::-1] if be else vec)[i]) * (base ** i)  # Lift digit to Integer and accumulate
    return num

m = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
ln = 4 # number of digits leaked
base = int(str(m)[:ln])+1 # 10**2 ~ 10**5
n_parts = 5 # number of parts in each number
n_nums = 2 # number of numbers
V = FreeModule(Zmod(base), n_parts)
print(f"Working with {base = }, {n_nums} numbers of {n_parts} digits each: {V}")

_target_x: list[int] | None = None

def gen_n(parts: list[int] | None = None, n_nums: int = n_nums) -> int:
    global V
    if parts:
        X = [t := V( parts )] + [t := flip(t) for i in range(n_nums-1)]
    else:
        X = [t := V(sorted(list(V.random_element())))] + [t := flip(t) for i in range(n_nums-1)]
        parts = list(map(int, X[0]))

    print("a_i:"); pprint(parts)
    X = list(map(to_integer, X))
    print("p_i:"); pprint(X)
    n = prod(X)
    # get_xi(_target_a)
    return n

def get_xi(ai: list[int]):
    global _target_x
    a, b, c, d, e = ai
    _target_x = [
        (a*e),
        (a*d + b*e),
        (a*c + b*d + c*e),
        (a*b + b*c + c*d + d*e),
        (a**2 + b**2 + c**2 + d**2 + e**2)
    ]
    # print("x_i:")
    # pprint(_target_x)

def solve_xi(n: int) -> Generator[tuple[int]] | None:
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
        1*base**n_nums,
        2*base**n_nums,
        3*base**n_nums,
        4*base**n_nums,
        5*base**n_nums
    ]

    load('https://raw.githubusercontent.com/TheBlupper/linineq/main/linineq.py')
    sols_xyz = solve_bounded_gen(matrix(M), b, lb, ub, solver='ppl')

    return sols_xyz

def solve_ai(partial: tuple[int]) -> list[int] | None: # x_i -> a_i5
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

from time import time
def measure_solve_ai(): # usually 0.2s
    global _target_x
    n = gen_n()
    start = time()
    ai = solve_ai(_target_x)
    print(f"Took {time() - start}s to solve for ai_s: {ai}")

def measure_solve_xi():
    global _target_x
    n = gen_n()
    sols_xi = solve_xi(n)
    for j, xi in tqdm(enumerate(sols_xi)):
        if all(i in _target_x for i in xi):
            print(f"\nSolved xi: {xi}\nat iteration {j}")
            break
    else:
        raise Exception("Not found fsr wth")

def solve_full_check(n: int | None = None):
    global _target_x
    if not n: n = gen_n()
    assert _target_x
    sols_xi = solve_xi(n)
    for xi in tqdm(sols_xi):
        if ai := solve_ai(xi):
            # print(f"\nSolved for ai_s: {ai}")
            assert all(i in _target_x for i in xi), f"Found solution for wrong xi_s"
            return sorted(ai)
        else:
            if all(i in _target_x for i in xi):
                raise Exception("Did not solve for correct xi_s")
    else:
        raise Exception("Did not find correct xi_s")

def solve_full(n: int):
    sols_xi = solve_xi(n)
    pbar = tqdm(sols_xi)
    for xi in pbar:
        ai = solve_ai(xi)
        pbar.set_description(str(ai))
        if ai:
            return sorted(ai)

    else:
        raise Exception("Did not find correct xi_s")

if __name__ == '__main__':
    # n = gen_n()
    n = 73886322605974788253560304554048
    print(f"Testing with n = {n}")
    print(f"\nSolved for ai_s: {solve_full(n)}")
    # measure_solve_ai()
    # measure_solve_xi()

    print("Done")
