from pwn import *
from Crypto.Util.number import *
import json

r = remote('localhost', 9999)

r.recvline()
c = json.loads(r.recvline().decode().strip())["C"]

possibles = set()

flags = set()
while len(flags) != 153:
    tosend = json.dumps({'func' : 'DEC', 'args' : [c]})
    r.sendline(tosend.encode())
    uh = json.loads(r.recvline().decode())['retn']
    flags.add(int(uh))
    print(len(flags))

ok = sorted(list(flags))
N = ok[-1] + ok[1]
print(f"{N = }")

mults = [long_to_bytes((inverse(2, N) * i) % N) for i in ok]
for i in mults:
    if b'nite' in i:
        print(i)