from random import *
from randcrack import RandCrack
from pwn import *
import hashlib
import HashTools

HOST = ...
PORT = ...
emojis = ['🍒', '🍋', '🍊', '🍇','🍉', '🍓', '🍍', '🍎','🍏', '🍐', '🍑', '🍈','🍌', '🥭', '🥝', '🥥']
hash_funcs = [hashlib.sha256]*1024+[hashlib.sha3_224]*1023+[hashlib.sha1]
user = 'user'

#r = remote(HOST,PORT)
r = process(['python','chall.py'],level='debug')
rc = RandCrack()

def emoji2val(e):
    val = ''
    for i in e:
        val = bin(emojis.index(i))[2:].zfill(4) + val
    return int(val,2)

def get_slotval(no=False):
    r.recvuntil(b'Enter your choice: ')
    r.sendline(b'1')
    data = r.recvuntil(b'Updated balance: $').decode('utf-8')
    wheel = ''
    for c in data:
        if c in emojis:
            wheel+=c
    if not no:
        rc.submit(emoji2val(wheel[:8]))
        rc.submit(emoji2val(wheel[8:]))
    print(emoji2val(wheel[8:]))

def submit_256(val):
    for i in range(8):  
        shift = i * 32
        part = (val >> shift) & 0xFFFFFFFF
        rc.submit(part)

def get_rouletteval():
    r.recvuntil(b'Enter your choice: ')
    r.sendline(b'2')
    r.sendline(b'1')
    r.sendline(b'R')
    r.recvuntil(b'the number is ')
    num = int(r.recvline().strip().decode())
    r.recvuntil(b'Updated balance: $')
    submit_256(num)
    
def forge_lottery(username,amount,vcode):
    original_data = (username+'|'+str(amount)).encode()
    append_data = b"|1000000000"
    magic = HashTools.new("sha1")
    new_data, new_code = magic.extension(
        secret_length=32,
        original_data=original_data,
        append_data=append_data,
        signature=vcode
    )
    return new_data,new_code

def get_lottery():
    shuffle(hash_funcs)
    sha1_idx = hash_funcs.index(hashlib.sha1)
    print(sha1_idx)
    found = False
    while not found:
        ticket_id = random.randint(1, 11)
        hash_idx = random.randint(0, len(hash_funcs) - 1)
        if ticket_id > 5 and hash_idx == sha1_idx:
            found = True
            print('found it')
            break
        r.recvuntil(b'Enter your choice: ')
        r.sendline(b'3')
        r.sendline(b'0')
    r.sendline(b'3')
    r.sendline(b'1')
    
    r.recvuntil(b'won! $')
    amount = int(r.recvline().strip().decode())
    r.recvuntil(b'data: ')
    vdata = r.recvline().strip().decode()
    r.recvuntil(b'code: ')
    vcode = r.recvline().strip().decode()
    return amount,vdata,vcode
        
r.recvuntil(b'username: ')
r.sendline(user.encode())

for _ in range(56):
    get_slotval()

for _ in range(64):
    get_rouletteval()

setstate((3, (*[int(''.join(map(str, rc.mt[i])), 2) for i in range(len(rc.mt))], 0), None))

amount,vdata,vcode = get_lottery()
ndata,ncode = forge_lottery(user,amount,vcode)
r.sendline(b'4')
r.sendline(ncode.encode())
r.sendline(ndata.hex().encode())
r.sendline(b'6')
r.recvuntil(b"Here's your flag: ")
print(r.recvline())