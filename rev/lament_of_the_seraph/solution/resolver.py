import pefile
import sys
import os

def rotl32(a, b):
    return ((a << b) & 0xFFFFFFFF) | (a >> (32 - b))

def get_hash(name):
    state = [len(name)] * 16
    b = name.encode()
    
    for i in range(min(len(b), 48)):
        state[i // 4] ^= b[i] << ((i % 4) * 8)
    
    state[0] ^= 0x48505253; state[5] ^= 0x45434E4C
    state[10] ^= 0x4554494E; state[15] ^= 0x35323032
    
    x = list(state)
    for _ in range(4):
        def qr(a,b,c,d):
            x[b] ^= rotl32((x[a]+x[d])&0xffffffff, 5)
            x[c] ^= rotl32((x[b]+x[a])&0xffffffff, 11)
            x[d] ^= rotl32((x[c]+x[b])&0xffffffff, 17)
            x[a] ^= rotl32((x[d]+x[c])&0xffffffff, 23)
        qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
        qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)

    res = 0
    for i in range(16): res ^= (x[i] + state[i]) & 0xFFFFFFFF
    return res

if len(sys.argv) < 2:
    print("Usage: py resolver.py <hash>")
    sys.exit()

target = int(sys.argv[1], 16) if "0x" in sys.argv[1] else int(sys.argv[1])
dlls = ["kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll", "crypt32.dll"]
path = r"C:\Windows\System32"

for dll in dlls:
    try:
        pe = pefile.PE(os.path.join(path, dll))
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name: continue
            name = exp.name.decode()
            if get_hash(name) == target:
                print(f"Found: {name} in {dll}")
                sys.exit()
    except Exception as e: 
        continue

print("Not found")
