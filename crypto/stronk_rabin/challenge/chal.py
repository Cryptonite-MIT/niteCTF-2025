from Crypto.Util.number import *
import stronk_rabin_api
import gmpy2, os, json

FUNC_MAP = {
    "DEC": stronk_rabin_api.DEC,
    "ENC" : stronk_rabin_api.ENC
}

def query(request : str):
    try:
        request = json.loads(request)
        func = FUNC_MAP[request['func']]
        args = request['args']
        retn = func(*args)
        resp = json.dumps({"retn": retn})
    except Exception as e:
        resp = json.dumps({"retn": str(e)})

    return resp
    
if __name__ == "__main__":
    print('Generating parameters... might take a second.. pls bear with me')
    while True:
        try:
            while True:
                    primes = [getPrime(256) for _ in range(4)]
                    if all(x % 4 == 3 for x in primes):
                        break

            p, q, r, s = primes
            n = p*q*r*s
            flag = bytes_to_long(b'nite{rabin_stronk?_no_r4bin_brok3n}' + os.urandom(93))
            assert flag < n
            assert 2*flag > n
            assert pow(flag, 2) > n
            break
        except Exception as e:
            continue

    stronk_rabin_api.set_primes(p, q, r, s)
    stronk_rabin_api.set_secret(flag)

    C = stronk_rabin_api.ENC(flag, n)

    assert int(gmpy2.iroot(C, 2)[0]) != flag

    print(json.dumps({'C' : C}))
    while True:
        try:
            res = query(input())
            print(res)
        except Exception as e:
            print(json.dumps({'error' : str(e)}))
            continue
