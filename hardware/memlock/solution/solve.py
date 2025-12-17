encrypted_flag = [
    0x93, 0x98, 0x83, 0x94, 0x8A, 0xBC, 0xC6, 0x8E,
    0xBC, 0xC2, 0xBC, 0xFF, 0x81, 0x98, 0x8E, 0xBC,
    0xC3, 0xBF, 0xBF, 0xC2, 0x93, 0x8E, 0xBC, 0x88,
    0xC4, 0x83, 0xC2, 0x81, 0xC0, 0x94, 0xC4, 0xAC
]

cipher = bytes(encrypted_flag)

def decrypt(cipher):
    keyA = 0xA3
    irq_n = 6
    vals = []

    for i, enc in enumerate(cipher):
        saved_B = 0x55 if i == 0 else 0x43
        A0 = keyA
        B0 = enc ^ 0x5C
        r1 = (A0 - B0) & 0xFF
        B1 = (saved_B ^ (irq_n << 3)) & 0xFF
        r2 = (r1 ^ B1) & 0xFF
        final = (r2 - 0x43) & 0xFF
        vals.append(final)

    bits = []
    for v in vals:
        for b in range(8):
            bits.append((v >> b) & 1)

    out = []
    for i in range(0, len(bits), 8):
        x = 0
        for j in range(8):
            x |= (bits[i + j] & 1) << j
        out.append(x)

    return bytes(out)

flag = decrypt(cipher)
print(flag.decode())
