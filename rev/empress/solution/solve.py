#!/usr/bin/env python3
"""
Handles crash entanglement [0-6] AND physics entanglement [17-22]
Plus gameplay accumulator for tile decryption


Usage: python solve.py <license_file> <your_fingerprint>
"""

import hashlib
import hmac
import struct
import sys

ENCRYPTION_KEY = b"ihatevms@2025"
MAGIC_SUM = 33
MOVEMENT_OFFSET = 17

# Binary format constants
MAGIC_NITE = 0x4554494E  # "NITE" in little endian
VERSION = 2

# Accumulator constants (must match SecureVM.cpp)
ACCUMULATOR_SEED = 0xDEADBEEF
KILL_GOOMBA_VALUE = 0x12345678
KILL_KOOPA_VALUE = 0x87654321
GOOMBA_KILLS = 16
KOOPA_KILLS = 1

def xor_crypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def compute_hmac_bytes(data: bytes, key: bytes) -> bytes:
    """Compute HMAC as raw bytes (not hex)"""
    return hmac.new(key, data, hashlib.sha256).digest()

def djb2_hash(s: str) -> int:
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h

def compute_expected_accumulator() -> int:
    """Compute expected accumulator value after killing all enemies"""
    acc = ACCUMULATOR_SEED
    acc = (acc + GOOMBA_KILLS * KILL_GOOMBA_VALUE) & 0xFFFFFFFF
    acc = (acc + KOOPA_KILLS * KILL_KOOPA_VALUE) & 0xFFFFFFFF
    return acc

def parse_binary_license(filepath: str) -> tuple:
    """Parse binary license file format v2"""
    with open(filepath, 'rb') as f:
        # Read header
        magic = struct.unpack('<I', f.read(4))[0]
        if magic != MAGIC_NITE:
            raise ValueError(f"Invalid magic: expected 0x{MAGIC_NITE:08X}, got 0x{magic:08X}")

        version = struct.unpack('<I', f.read(4))[0]
        if version != VERSION:
            raise ValueError(f"Invalid version: expected {VERSION}, got {version}")

        # Read HMAC
        hmac_len = struct.unpack('<I', f.read(4))[0]
        stored_hmac = f.read(hmac_len)

        # Read encrypted data
        data_len = struct.unpack('<I', f.read(4))[0]
        encrypted_data = f.read(data_len)

    return stored_hmac, encrypted_data

def decrypt_license_data(encrypted: bytes) -> dict:
    """Decrypt and parse license data"""
    decrypted = xor_crypt(encrypted, ENCRYPTION_KEY)
    data = {}
    for line in decrypted.decode('utf-8', errors='ignore').split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value
    return data

def write_binary_license(filepath: str, license_text: str):
    """Write license in binary format v2"""
    encrypted = xor_crypt(license_text.encode(), ENCRYPTION_KEY)
    hmac_bytes = compute_hmac_bytes(encrypted, ENCRYPTION_KEY)

    with open(filepath, 'wb') as f:
        # Magic
        f.write(struct.pack('<I', MAGIC_NITE))
        # Version
        f.write(struct.pack('<I', VERSION))
        # HMAC length and data
        f.write(struct.pack('<I', len(hmac_bytes)))
        f.write(hmac_bytes)
        # Encrypted data length and data
        f.write(struct.pack('<I', len(encrypted)))
        f.write(encrypted)

# Crash entanglement [0-6]: (hash >> (i*3)) & 0xFF
def get_crash_comps(hw_hash): return [(hw_hash >> (i * 3)) & 0xFF for i in range(7)]

# Physics entanglement [17-22]: (hash >> ((i+7) % 32)) & 0xFF
def get_physics_comps(hw_hash): return [(hw_hash >> ((i + 7) % 32)) & 0xFF for i in range(6)]

def de_entangle(vals, comps): return [vals[i] ^ comps[i] for i in range(len(comps))]
def re_entangle(vals, comps): return [vals[i] ^ comps[i] for i in range(len(comps))]

def generate_license(license_path: str, my_fingerprint: str):
    print("[*] DRM Keygen (Binary Format v2)")
    print("=" * 60)

    stored_hmac, encrypted_data = parse_binary_license(license_path)
    computed_hmac = compute_hmac_bytes(encrypted_data, ENCRYPTION_KEY)

    if computed_hmac == stored_hmac:
        print("[+] HMAC verified!")
    else:
        print("[!] HMAC mismatch - file may be corrupted")

    license_data = decrypt_license_data(encrypted_data)
    original_fp = license_data['HARDWARE_FP']

    print(f"[+] Original FP: {original_fp[:40]}...")
    print(f"[+] Target FP:   {my_fingerprint[:40]}...")

    constants = [int(x) for x in license_data['SECURE_CONSTANTS'].split(',') if x]
    original_hash = djb2_hash(original_fp)
    my_hash = djb2_hash(my_fingerprint)

    print(f"[+] Original Hash: 0x{original_hash:08X}")
    print(f"[+] Target Hash:   0x{my_hash:08X}")

    # Crash entanglement [0-6]
    print("\n[+] Crash entanglement [0-6]...")
    crash_orig = de_entangle(constants[0:7], get_crash_comps(original_hash))
    print(f"    Original: {crash_orig}, Sum: {sum(crash_orig)}")
    if sum(crash_orig) != MAGIC_SUM:
        print("[!] ERROR: Sum != 33")
        return False
    crash_new = re_entangle(crash_orig, get_crash_comps(my_hash))
    print(f"    New: {crash_new}")

    # Physics entanglement [17-22]
    print("\n[+] Physics entanglement [17-22]...")
    phys_orig = de_entangle(constants[17:23], get_physics_comps(original_hash))
    print(f"    Original: MaxMove={phys_orig[0]}, Jump={phys_orig[1]/100}, Gravity={phys_orig[2]/100}")
    phys_new = re_entangle(phys_orig, get_physics_comps(my_hash))
    print(f"    New: {phys_new}")

    # Accumulator info
    expected_acc = compute_expected_accumulator()
    print(f"\n[+] Gameplay Accumulator:")
    print(f"    Kill {GOOMBA_KILLS} Goombas + {KOOPA_KILLS} Koopa")
    print(f"    Expected: 0x{expected_acc:08X}")

    # Build new constants
    new_constants = constants.copy()
    new_constants[0:7] = crash_new
    new_constants[17:23] = phys_new

    # Build license
    new_license = f"""LICENSE_KEY={license_data.get('LICENSE_KEY', 'KEY')}
HARDWARE_FP={my_fingerprint}
ISSUE_DATE={license_data.get('ISSUE_DATE', '0')}
EXPIRY_DATE=9999999999
IS_PERPETUAL=1
IS_ACTIVATED=1
MAX_ACTIVATIONS=999
CURRENT_ACTIVATIONS=1
SECURE_CONSTANTS={','.join(map(str, new_constants))}
"""

    # Write in binary format
    write_binary_license('.game_license', new_license)

    print("\n" + "=" * 60)
    print("[✓] License generated: .game_license (binary format v2)")
    print("[*] Run ./mario and complete level 1-1 for the flag!")
    print(f"[*] You MUST kill all {GOOMBA_KILLS} Goombas and {KOOPA_KILLS} Koopa!")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python solve.py <license_file> <your_fingerprint>")
        print("\nGet fingerprint: ./license_tool info")
        sys.exit(1)
    generate_license(sys.argv[1], sys.argv[2])
