# NiteBus

**Flag:** `nite{th3_wh33l5_0n_th3_n1tbu5_g0_up_&_d0wn_4ll_thru_th3_t0wn}`

Since, the binary given is compiled in the ARM64 architecture, we need the correct toolchain (`qemu-aarch64`) for running the binary.

To send input to the binary, we need to follow the correct packet format for MODBUS, as described in the binary ie:

1. Function ID
2. Function Code
3. Length
4. Data

Now, there is a Buffer Overflow in 0x42 function code, `Upload Control Program` and a format string leak in 0x8 function code, `Diagnostics`.
Also, the string `/bin/sh` is defined at 0x490040,
which makes it clear that you need to get shell.

Exploit is to:

Get a stack leak using the format string function and then utilize ROP using the correct gadgets to load the `/bin/sh` string and get shell.

[Solve script](solve.py)
