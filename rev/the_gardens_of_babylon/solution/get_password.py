from z3 import *

def reverse_complex_hash(final_state_bytes: bytes) -> bytes:
    final_p1 = int.from_bytes(final_state_bytes[0:4], 'little')
    final_p2 = int.from_bytes(final_state_bytes[4:8], 'little')
    final_p3 = int.from_bytes(final_state_bytes[8:12], 'little')
    final_p4 = int.from_bytes(final_state_bytes[12:16], 'little')

    print("Final state:")
    print(f"  p1 = 0x{final_p1:08x}")
    print(f"  p2 = 0x{final_p2:08x}")
    print(f"  p3 = 0x{final_p3:08x}")
    print(f"  p4 = 0x{final_p4:08x}")

    s = Solver()
    s.set("timeout", 300000)

    orig_p1 = BitVec('orig_p1', 32)
    orig_p2 = BitVec('orig_p2', 32)
    orig_p3 = BitVec('orig_p3', 32)
    orig_p4 = BitVec('orig_p4', 32)

    for i in range(4):
        s.add(Extract(i*8+7, i*8, orig_p1) >= 32)
        s.add(Extract(i*8+7, i*8, orig_p1) <= 126)
        s.add(Extract(i*8+7, i*8, orig_p2) >= 32)
        s.add(Extract(i*8+7, i*8, orig_p2) <= 126)
        s.add(Extract(i*8+7, i*8, orig_p3) >= 32)
        s.add(Extract(i*8+7, i*8, orig_p3) <= 126)
        s.add(Extract(i*8+7, i*8, orig_p4) >= 32)
        s.add(Extract(i*8+7, i*8, orig_p4) <= 126)

    p1, p2, p3, p4 = orig_p1, orig_p2, orig_p3, orig_p4

    for r in range(16):
        print(f"Round {r+1}")

        new_p1 = (p1 + p2) ^ BitVecVal(0x9e3779b9, 32)
        new_p2 = (p2 + p3) ^ BitVecVal(0x21524111, 32)
        new_p3 = (p3 + p4) ^ BitVecVal(0x12345678, 32)
        new_p4 = (p4 + new_p1) ^ BitVecVal(0x87654321, 32)

        new_p1 = new_p1 * BitVecVal(3, 32)
        new_p2 = new_p2 * BitVecVal(5, 32)
        new_p3 = new_p3 * BitVecVal(7, 32)
        new_p4 = new_p4 * BitVecVal(9, 32)

        p1, p2, p3, p4 = new_p2, new_p3, new_p4, new_p1

    s.add(p1 == final_p1)
    s.add(p2 == final_p2)
    s.add(p3 == final_p3)
    s.add(p4 == final_p4)

    print("Solving...")

    result = s.check()
    if result == sat:
        m = s.model()
        rp1 = m[orig_p1].as_long()
        rp2 = m[orig_p2].as_long()
        rp3 = m[orig_p3].as_long()
        rp4 = m[orig_p4].as_long()

        print("Solution:")
        print(f"  orig_p1 = 0x{rp1:08x}")
        print(f"  orig_p2 = 0x{rp2:08x}")
        print(f"  orig_p3 = 0x{rp3:08x}")
        print(f"  orig_p4 = 0x{rp4:08x}")

        result_bytes = (
            rp1.to_bytes(4, 'little') +
            rp2.to_bytes(4, 'little') +
            rp3.to_bytes(4, 'little') +
            rp4.to_bytes(4, 'little')
        )

        print("Password (hex):", result_bytes.hex())
        print("Password (ascii):", result_bytes.decode('ascii', errors='replace'))
        return result_bytes

    if result == unknown:
        print("Solver returned: unknown")
        return None

    print("No solution.")
    return None


def verify_forward(password_bytes: bytes, expected_final: bytes) -> bool:
    p1 = int.from_bytes(password_bytes[0:4], 'little')
    p2 = int.from_bytes(password_bytes[4:8], 'little')
    p3 = int.from_bytes(password_bytes[8:12], 'little')
    p4 = int.from_bytes(password_bytes[12:16], 'little')

    print("Verifying...")
    print(f"  Initial: p1=0x{p1:08x} p2=0x{p2:08x} p3=0x{p3:08x} p4=0x{p4:08x}")

    for _ in range(16):
        new_p1 = ((p1 + p2) ^ 0x9e3779b9) & 0xFFFFFFFF
        new_p2 = ((p2 + p3) ^ 0x21524111) & 0xFFFFFFFF
        new_p3 = ((p3 + p4) ^ 0x12345678) & 0xFFFFFFFF
        new_p4 = ((p4 + new_p1) ^ 0x87654321) & 0xFFFFFFFF

        new_p1 = (new_p1 * 3) & 0xFFFFFFFF
        new_p2 = (new_p2 * 5) & 0xFFFFFFFF
        new_p3 = (new_p3 * 7) & 0xFFFFFFFF
        new_p4 = (new_p4 * 9) & 0xFFFFFFFF

        p1, p2, p3, p4 = new_p2, new_p3, new_p4, new_p1

    print(f"  Final:   p1=0x{p1:08x} p2=0x{p2:08x} p3=0x{p3:08x} p4=0x{p4:08x}")

    out = (
        p1.to_bytes(4, 'little') +
        p2.to_bytes(4, 'little') +
        p3.to_bytes(4, 'little') +
        p4.to_bytes(4, 'little')
    )

    ok = out == expected_final
    print("Verification:", "OK" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    final_p1 = 0x9051fa6d
    final_p2 = 0xaedbbadb
    final_p3 = 0xf961dac0
    final_p4 = 0x1f98a2a8

    final_state = (
        final_p1.to_bytes(4, 'little') +
        final_p2.to_bytes(4, 'little') +
        final_p3.to_bytes(4, 'little') +
        final_p4.to_bytes(4, 'little')
    )

    original_password = reverse_complex_hash(final_state)

    if original_password:
        verify_forward(original_password, final_state)
        print("Recovered:", original_password.hex())
