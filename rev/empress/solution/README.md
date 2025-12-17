# Empress

**Author:** `a1ia5`

**Flag:** `nite{m4r10_drm_sl4y3r_m3l4g3a1}`

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [License File Format](#license-file-format)
4. [Hardware Fingerprinting System](#hardware-fingerprinting-system)
5. [The Entanglement Crash Mechanism](#the-entanglement-crash-mechanism)
6. [Physics Entanglement](#physics-entanglement)
7. [The Secure Virtual Machine](#the-secure-virtual-machine)
8. [Gameplay Accumulator & Flag Decryption](#gameplay-accumulator--flag-decryption)
9. [Crafting the Keygen](#crafting-the-keygen)
10. [Getting the Flag](#getting-the-flag)

## Challenge Overview

We receive a stripped Linux ELF binary `mario` — a fully playable Super Mario Bros clone. However, running it immediately crashes:

```bash
$ file mario
mario: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),
       statically linked, BuildID[sha1]=..., stripped

$ ./mario
Segmentation fault (core dumped)
```

**Objective:** Understand the DRM protection scheme and craft a valid license file to play the game and reveal the hidden flag.

## Initial Analysis

### Tracing the Crash

Using `strace` to understand what the binary does before crashing:

**Finding #1:** The binary attempts to open `.game_license` and crashes when it doesn't exist.

Let's try creating an empty file:

```bash
$ touch .game_license
$ ./mario
Segmentation fault (core dumped)
```

Still crashes. The file format matters.

### Loading into Ghidra/IDA

Opening in IDA Pro with Hex-Rays decompiler reveals:

- **442,005 lines** of decompiled C code
- All functions stripped to `sub_XXXXX` naming
- OpenSSL library **statically linked** (we see error strings like `"../crypto/ct/ct_sct.c"`, `"SCT_CTX_verify"`)
- SDL2 graphics library linked dynamically

The static linking of OpenSSL means cryptographic operations are embedded in the binary — HMAC, SHA256, etc.

## License File Format

### Finding the License Parser

Starting from the failed `openat()` call, we trace execution to find the license parsing routine. In the decompiled code, we identify `sub_6E280` as the main license validation function.

### sub_6E280 — License Validation (Decompiled)

```c
unsigned __int64 __fastcall sub_6E280(__int64 a1, __m128i a2) {
    uint32_t magic, version, hmac_len, data_len;
    unsigned char stored_hmac[64];
    unsigned char computed_hmac[64];
    char *encrypted_data;
    char *decrypted_data;

    // Open license file
    std::ifstream file(".game_license", std::ios::binary);
    if (!file.is_open()) {
        return LICENSE_NOT_ACTIVATED;  // Triggers crash path
    }

    // Read magic number (4 bytes)
    file.read((char*)&magic, 4);
    if (magic != 0x4554494E) {  // "NITE" in little-endian
        return LICENSE_INVALID_KEY;
    }

    // Read version (4 bytes)
    file.read((char*)&version, 4);
    if (version != 2) {
        return LICENSE_INVALID_KEY;
    }

    // Read HMAC
    file.read((char*)&hmac_len, 4);
    file.read((char*)stored_hmac, hmac_len);

    // Read encrypted data
    file.read((char*)&data_len, 4);
    encrypted_data = malloc(data_len);
    file.read(encrypted_data, data_len);

    // Verify HMAC-SHA256
    HMAC(EVP_sha256(), "ihatevms@2025", 13,
         encrypted_data, data_len,
         computed_hmac, &hmac_len);

    if (memcmp(computed_hmac, stored_hmac, hmac_len) != 0) {
        // "Licence integrity check failed"
        return LICENSE_INVALID_KEY;
    }

    // XOR decrypt
    for (int i = 0; i < data_len; i++) {
        encrypted_data[i] ^= "ihatevms@2025"[i % 13];
    }

    // Parse decrypted key=value pairs
    // ...
}
```

### Binary License Format Specification

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Magic: `0x4554494E` ("NITE") |
| 0x04 | 4 | Version: `0x00000002` |
| 0x08 | 4 | HMAC length (typically 32) |
| 0x0C | N | HMAC-SHA256 bytes |
| 0x0C+N | 4 | Encrypted data length |
| 0x10+N | M | XOR-encrypted license data |

### Discovering the Encryption Key

The XOR key and HMAC key are the same. We find it by locating the string reference in the decryption loop:

```bash
$ strings mario | grep "@"
ihatevms@2025
```

Or in the decompiled code, the key is loaded from `.rodata` at a specific offset and used in both the XOR loop and HMAC call.

### Decrypted License Format

After XOR decryption, the license is a newline-separated text:

```
LICENSE_KEY=XXXX-XXXX-XXXX-XXXX
HARDWARE_FP=<hardware_fingerprint_string>
ISSUE_DATE=1702500000
EXPIRY_DATE=9999999999
IS_PERPETUAL=1
IS_ACTIVATED=1
MAX_ACTIVATIONS=1
CURRENT_ACTIVATIONS=1
SECURE_CONSTANTS=val0,val1,val2,...,valN
```

The `SECURE_CONSTANTS` field contains comma-separated integers that control the DRM and game behavior.

## Hardware Fingerprinting System

### sub_6C1C8 — Fingerprint Collection

The binary collects extensive hardware information to create a machine-unique fingerprint:

```c
unsigned __int64 __fastcall sub_6C1C8(__int64 fp_obj) {
    char buffer[4096];
    FILE *f;
    struct utsname uts;
    struct sysinfo si;
    struct ifaddrs *ifap, *ifa;

    // 1. CPU Information from /proc/cpuinfo
    f = fopen("/proc/cpuinfo", "r");
    while (fgets(buffer, sizeof(buffer), f)) {
        if (strstr(buffer, "model name")) {
            // Extract CPU model
            append_to_fingerprint(fp_obj, parse_value(buffer));
        }
        if (strstr(buffer, "cpu cores")) {
            append_to_fingerprint(fp_obj, parse_value(buffer));
        }
    }
    fclose(f);

    // 2. System memory
    sysinfo(&si);
    sprintf(buffer, "%lu", si.totalram);
    append_to_fingerprint(fp_obj, buffer);

    // 3. Kernel information
    uname(&uts);
    append_to_fingerprint(fp_obj, uts.machine);

    // 4. Network interfaces (MAC addresses)
    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            // Extract MAC address
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            format_mac(buffer, s->sll_addr);
            append_to_fingerprint(fp_obj, buffer);
        }
    }
    freeifaddrs(ifap);

    // 5. Disk serial numbers
    // Reads from /sys/block/*/device/serial or uses hdparm
    collect_disk_serials(fp_obj);

    // Final fingerprint is concatenated string of all values
}
```

### sub_6D392 — djb2 Hash Function

The fingerprint string is hashed using the classic djb2 algorithm:

```c
uint32_t __fastcall sub_6D392(__int64 fingerprint_str) {
    uint32_t hash = 5381;
    char *str = (char*)fingerprint_str;
    char c;

    while ((c = *str++) != 0) {
        hash = ((hash << 5) + hash) + (uint32_t)c;
        // Equivalent to: hash = hash * 33 + c
    }

    return hash;
}
```

**Key constant:** The initial value `5381` is a well-known djb2 signature, making this algorithm easy to identify during reverse engineering.

## The Entanglement Crash Mechanism

This is the most sophisticated protection layer. Unlike traditional DRM that uses conditional branches (`if (!valid) exit()`), this protection uses **pure arithmetic** to cause crashes on unauthorized machines.

### sub_6D530 — Setting Up Entanglement

The first 7 values in `SECURE_CONSTANTS` are **hardware-entangled values**:

```c
void __fastcall sub_6D530(__int64 license_data) {
    uint32_t hw_hash = sub_6D392(current_fingerprint);  // djb2 hash
    int entangled_sum = 0;
    int delta;

    // XOR each constant with a portion of the hardware hash
    for (int i = 0; i < 7; i++) {
        int hw_component = (hw_hash >> (i * 3)) & 0xFF;
        int entangled_val = license_constants[i] ^ hw_component;
        entangled_sum += entangled_val;
    }

    // Store the divisor (used later for crash/no-crash)
    g_entangled_divisor = entangled_sum + 1;

    // Compute pointer offset
    const int MAGIC_SUM = 33;  // Expected: 10+5+6+6+2+3+1 = 33
    delta = entangled_sum - MAGIC_SUM;

    // Pointer arithmetic for crash
    uintptr_t valid_addr = (uintptr_t)&g_entangled_target;
    uintptr_t computed_addr = valid_addr + (uintptr_t)(delta * 0x1000);
    g_entangled_write_ptr = (volatile int*)computed_addr;
}
```

### The Mathematics of Crashing

| Scenario | hw_hash | Entangled Sum | Divisor | Delta | Pointer |
|----------|---------|---------------|---------|-------|---------|
| **Correct machine** | Matches license | 33 | 34 | 0 | Valid address |
| **Wrong machine** | Different | Random | Random (could be 0!) | Non-zero | Invalid address |

### sub_6D5C6 — The Entangled Operation

This function is called during game initialization and **will crash on wrong hardware**:

```c
int __fastcall sub_6D5C6() {
    volatile int result;

    // Division - crashes if g_entangled_divisor is 0
    // (happens when entangled_sum = -1, which is unlikely but possible)
    result = 1000000 / g_entangled_divisor;

    // Memory write - crashes if pointer is invalid
    // On wrong hardware: delta != 0, so pointer = valid_addr + garbage
    // This points into unmapped memory, causing SIGSEGV
    *g_entangled_write_ptr = 0xDEAD;

    return result;
}
```

### Why This is Unpatchable

Traditional DRM:
```c
if (!license_valid) {
    exit(1);  // Can be NOPed out
}
```

Entanglement DRM:
```c
// No conditional branches!
divisor = entangled_sum + 1;
result = 1000000 / divisor;  // Arithmetic, not a branch
*computed_ptr = 0xDEAD;       // Pointer math, not a branch
```

You cannot patch out arithmetic. The crash is **inherent in the mathematics**.

## Physics Entanglement

Beyond crash protection, the **player physics** are also hardware-entangled.

### sub_74236 — Movement Physics

```c
MovementPhysics __fastcall sub_74236(float *player, __int64 license_data) {
    MovementPhysics physics;
    uint32_t hw_hash = sub_6D392(current_fingerprint);

    // Constants at indices [17-22] are physics values
    // They're stored XOR'd with hw_hash components

    int raw_maxMove = license_constants[17] ^
                      ((hw_hash >> ((0 + 7) % 32)) & 0xFF);
    int raw_jumpSpeed = license_constants[18] ^
                        ((hw_hash >> ((1 + 7) % 32)) & 0xFF);
    int raw_gravity = license_constants[19] ^
                      ((hw_hash >> ((2 + 7) % 32)) & 0xFF);
    int raw_decayFast = license_constants[20] ^
                        ((hw_hash >> ((3 + 7) % 32)) & 0xFF);
    int raw_decaySlow = license_constants[21] ^
                        ((hw_hash >> ((4 + 7) % 32)) & 0xFF);
    int raw_minJump = license_constants[22] ^
                      ((hw_hash >> ((5 + 7) % 32)) & 0xFF);

    // Convert to floats
    physics.maxMoveSpeed = raw_maxMove;                    // Expected: 4
    physics.startJumpSpeed = raw_jumpSpeed / 100.0f;       // Expected: 10.0
    physics.gravityMultiplier = raw_gravity / 100.0f;      // Expected: 1.05
    physics.jumpDecayFast = raw_decayFast / 1000.0f;       // Expected: 0.850
    physics.jumpDecaySlow = raw_decaySlow / 1000.0f;       // Expected: 0.950
    physics.minJumpSpeed = raw_minJump / 100.0f;           // Expected: 2.5

    // Sanity check for valid ranges
    if (physics.maxMoveSpeed >= 1 && physics.maxMoveSpeed <= 10 &&
        physics.startJumpSpeed >= 5.0f && physics.startJumpSpeed <= 20.0f) {
        physics.isValid = true;
    } else {
        physics.isValid = false;  // Broken physics
    }

    return physics;
}
```

On **wrong hardware**, de-entanglement produces garbage values:
- `maxMoveSpeed` could be 0 (can't move) or 255 (flies off screen)
- `gravityMultiplier` could be 50.0 (instant fall) or 0.01 (floats forever)

Even if you somehow bypass the crash, the game is **unplayable**.

## The Secure Virtual Machine

Critical game logic is protected by a custom bytecode VM with encrypted opcodes.

### sub_6EFFC — VM Execution

```c
int64_t __fastcall sub_6EFFC(__int64 program, __int64 constants, ...) {
    VM_Context ctx;
    ctx.stack = malloc(1024 * sizeof(int64_t));
    ctx.sp = 0;
    ctx.registers = calloc(16, sizeof(int64_t));
    ctx.rolling_key = 0xAA;  // Initial key for opcode decryption

    for (int pc = 0; pc < program_len; pc++) {
        uint8_t encrypted_op = program[pc * 2];
        int operand = program[pc * 2 + 1];

        // Rolling opcode decryption
        uint8_t real_op = (encrypted_op ^ ctx.rolling_key) % 120;
        ctx.rolling_key += encrypted_op;  // Key evolves

        switch (real_op) {
            case OP_LOAD_CONST:  // 0
                ctx.stack[ctx.sp++] = constants[operand];
                break;

            case OP_PUSH:  // 1
                ctx.stack[ctx.sp++] = operand;
                break;

            case OP_ADD:  // 2
                b = ctx.stack[--ctx.sp];
                a = ctx.stack[--ctx.sp];
                ctx.stack[ctx.sp++] = a + b;
                break;

            case OP_MUL:  // 4
                b = ctx.stack[--ctx.sp];
                a = ctx.stack[--ctx.sp];
                ctx.stack[ctx.sp++] = a * b;
                break;

            case OP_XOR:  // 10
                b = ctx.stack[--ctx.sp];
                a = ctx.stack[--ctx.sp];
                ctx.stack[ctx.sp++] = a ^ b;
                break;

            case OP_STORE:  // 5
                ctx.registers[operand] = ctx.stack[--ctx.sp];
                break;

            case OP_RETURN:  // 11
                return ctx.registers[operand];

            case OP_CRASH:  // 99
                // Deliberately corrupts entanglement
                g_entangled_divisor = 0;
                g_entangled_write_ptr = NULL;
                sub_6D5C6();  // Will crash
                break;
        }
    }

    return ctx.stack[ctx.sp - 1];
}
```

### Rolling Opcode Encryption

The VM opcodes are XOR-encrypted with a rolling key:

```
Initial key: 0xAA
Instruction 1: real_op = (encrypted_op ^ 0xAA) % 120; key += encrypted_op
Instruction 2: real_op = (encrypted_op ^ new_key) % 120; key += encrypted_op
...
```

This makes static analysis harder — you can't just look up opcode values without simulating the key evolution.

### VM Programs in License

The license contains embedded VM bytecode programs:
- **Map initialization** (spawn position calculation)
- **Coin collection handler**
- **Victory animation controller**
- **Flag tile decryption**

## Gameplay Accumulator & Flag Decryption

The flag is **not stored anywhere in the binary**. It's mathematically derived from gameplay.

### sub_99B48 — Enemy Kill Handler

```c
// Global accumulator, starts at seed value
uint32_t g_gameplay_accumulator = 0xDEADBEEF;

void __fastcall sub_99B48(__int64 enemy, int enemy_type) {
    // Order-independent: using addition, not XOR with position
    if (enemy_type == 0) {  // Goomba
        g_gameplay_accumulator += 0x12345678;
    } else {  // Koopa
        g_gameplay_accumulator += 0x87654321;
    }
}
```

### Expected Accumulator Value

Level 1-1 has:
- **16 Goombas**
- **1 Koopa**

```python
SEED = 0xDEADBEEF
GOOMBA_VAL = 0x12345678
KOOPA_VAL = 0x87654321

expected = SEED
expected = (expected + 16 * GOOMBA_VAL) & 0xFFFFFFFF
expected = (expected + 1 * KOOPA_VAL) & 0xFFFFFFFF
# expected = 0x????????
```

### Flag Tile Decryption

The flag is stored as encrypted tile coordinates. At victory, they're decrypted using the gameplay accumulator:

```c
void unlock_flag_tiles() {
    uint32_t gameplay_key = g_gameplay_accumulator;

    for (int i = 0; i < tile_count; i++) {
        int encrypted_packed = license_constants[tile_start + i];

        // Per-tile key derivation
        uint32_t tile_key = gameplay_key ^ ((uint32_t)i * 0xABCD);
        int decrypted_packed = encrypted_packed ^ (int)(tile_key & 0xFFFFFFFF);

        // Unpack tile coordinates
        int x = decrypted_packed & 0xFFFF;
        int y = (decrypted_packed >> 16) & 0xFFFF;

        // Sanity check
        if (x > 1000 || y > 1000) {
            continue;  // Garbage tile, wrong accumulator
        }

        flag_tiles.push_back({x, y});
    }
}
```

If you **skip enemies**, the accumulator is wrong, and the XOR decryption produces garbage coordinates — no visible flag.

## Crafting the Keygen

### Complete Keygen Script

```python
#!/usr/bin/env python3
"""
Mario Crackme Keygen
Handles: Crash entanglement [0-6], Physics entanglement [17-22]
         Gameplay accumulator for tile decryption
"""

import hashlib
import hmac
import struct
import sys

# Constants from reverse engineering
ENCRYPTION_KEY = b"ihatevms@2025"
MAGIC_NITE = 0x4554494E  # "NITE"
VERSION = 2
MAGIC_SUM = 33  # Expected sum of de-entangled crash constants

# Gameplay accumulator constants
ACCUMULATOR_SEED = 0xDEADBEEF
KILL_GOOMBA_VALUE = 0x12345678
KILL_KOOPA_VALUE = 0x87654321
GOOMBA_KILLS = 16
KOOPA_KILLS = 1


def djb2_hash(s: str) -> int:
    """djb2 hash function - must match binary exactly"""
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """XOR encryption/decryption"""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def compute_hmac(data: bytes, key: bytes) -> bytes:
    """HMAC-SHA256"""
    return hmac.new(key, data, hashlib.sha256).digest()


def get_crash_components(hw_hash: int) -> list:
    """Extract crash entanglement components from hw hash"""
    return [(hw_hash >> (i * 3)) & 0xFF for i in range(7)]


def get_physics_components(hw_hash: int) -> list:
    """Extract physics entanglement components from hw hash"""
    return [(hw_hash >> ((i + 7) % 32)) & 0xFF for i in range(6)]


def de_entangle(values: list, components: list) -> list:
    """Remove hardware entanglement"""
    return [values[i] ^ components[i] for i in range(len(components))]


def re_entangle(values: list, components: list) -> list:
    """Apply hardware entanglement for target machine"""
    return [values[i] ^ components[i] for i in range(len(components))]


def compute_expected_accumulator() -> int:
    """Compute expected accumulator after killing all enemies"""
    acc = ACCUMULATOR_SEED
    acc = (acc + GOOMBA_KILLS * KILL_GOOMBA_VALUE) & 0xFFFFFFFF
    acc = (acc + KOOPA_KILLS * KILL_KOOPA_VALUE) & 0xFFFFFFFF
    return acc


def parse_binary_license(filepath: str) -> tuple:
    """Parse binary license file format v2"""
    with open(filepath, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        if magic != MAGIC_NITE:
            raise ValueError(f"Bad magic: 0x{magic:08X}")

        version = struct.unpack('<I', f.read(4))[0]
        if version != VERSION:
            raise ValueError(f"Bad version: {version}")

        hmac_len = struct.unpack('<I', f.read(4))[0]
        stored_hmac = f.read(hmac_len)

        data_len = struct.unpack('<I', f.read(4))[0]
        encrypted_data = f.read(data_len)

    return stored_hmac, encrypted_data


def decrypt_license(encrypted: bytes) -> dict:
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
    hmac_bytes = compute_hmac(encrypted, ENCRYPTION_KEY)

    with open(filepath, 'wb') as f:
        f.write(struct.pack('<I', MAGIC_NITE))
        f.write(struct.pack('<I', VERSION))
        f.write(struct.pack('<I', len(hmac_bytes)))
        f.write(hmac_bytes)
        f.write(struct.pack('<I', len(encrypted)))
        f.write(encrypted)


def generate_license(original_license: str, target_fingerprint: str):
    """Generate license for target machine"""
    print("[*] Mario Crackme Keygen")
    print("=" * 70)

    # Parse original license
    stored_hmac, encrypted_data = parse_binary_license(original_license)
    computed_hmac = compute_hmac(encrypted_data, ENCRYPTION_KEY)

    if computed_hmac == stored_hmac:
        print("[+] HMAC verification: PASSED")
    else:
        print("[!] HMAC verification: FAILED (corrupted license)")
        return False

    # Decrypt license data
    license_data = decrypt_license(encrypted_data)
    original_fp = license_data['HARDWARE_FP']
    constants = [int(x) for x in license_data['SECURE_CONSTANTS'].split(',') if x]

    print(f"[+] Original fingerprint: {original_fp[:50]}...")
    print(f"[+] Target fingerprint:   {target_fingerprint[:50]}...")

    # Compute hashes
    original_hash = djb2_hash(original_fp)
    target_hash = djb2_hash(target_fingerprint)

    print(f"[+] Original djb2 hash: 0x{original_hash:08X}")
    print(f"[+] Target djb2 hash:   0x{target_hash:08X}")

    # =================================================================
    # CRASH ENTANGLEMENT [indices 0-6]
    # =================================================================
    print("\n[*] Processing crash entanglement (indices 0-6)...")

    crash_original = de_entangle(constants[0:7],
                                  get_crash_components(original_hash))
    print(f"    De-entangled values: {crash_original}")
    print(f"    Sum: {sum(crash_original)} (expected: {MAGIC_SUM})")

    if sum(crash_original) != MAGIC_SUM:
        print("[!] ERROR: Sum mismatch - invalid source license!")
        return False

    crash_new = re_entangle(crash_original,
                            get_crash_components(target_hash))
    print(f"    Re-entangled for target: {crash_new}")

    # =================================================================
    # PHYSICS ENTANGLEMENT [indices 17-22]
    # =================================================================
    print("\n[*] Processing physics entanglement (indices 17-22)...")

    physics_original = de_entangle(constants[17:23],
                                   get_physics_components(original_hash))
    print(f"    De-entangled physics:")
    print(f"      MaxMove:    {physics_original[0]}")
    print(f"      JumpSpeed:  {physics_original[1]/100:.2f}")
    print(f"      Gravity:    {physics_original[2]/100:.2f}")
    print(f"      DecayFast:  {physics_original[3]/1000:.3f}")
    print(f"      DecaySlow:  {physics_original[4]/1000:.3f}")
    print(f"      MinJump:    {physics_original[5]/100:.2f}")

    physics_new = re_entangle(physics_original,
                              get_physics_components(target_hash))
    print(f"    Re-entangled for target: {physics_new}")

    # =================================================================
    # GAMEPLAY ACCUMULATOR INFO
    # =================================================================
    expected_acc = compute_expected_accumulator()
    print(f"\n[*] Gameplay accumulator:")
    print(f"    Seed: 0x{ACCUMULATOR_SEED:08X}")
    print(f"    After {GOOMBA_KILLS} Goombas + {KOOPA_KILLS} Koopa: 0x{expected_acc:08X}")
    print(f"    You MUST kill all enemies to decrypt the flag!")

    # =================================================================
    # BUILD NEW LICENSE
    # =================================================================
    new_constants = constants.copy()
    new_constants[0:7] = crash_new
    new_constants[17:23] = physics_new

    new_license = f"""LICENSE_KEY={license_data.get('LICENSE_KEY', 'XXXX-XXXX-XXXX-XXXX')}
HARDWARE_FP={target_fingerprint}
ISSUE_DATE={license_data.get('ISSUE_DATE', '0')}
EXPIRY_DATE=9999999999
IS_PERPETUAL=1
IS_ACTIVATED=1
MAX_ACTIVATIONS=999
CURRENT_ACTIVATIONS=1
SECURE_CONSTANTS={','.join(map(str, new_constants))}
"""

    # Write output
    write_binary_license('.game_license', new_license)

    print("\n" + "=" * 70)
    print("[✓] License generated: .game_license")
    print("[*] Place in game directory and run ./mario")
    print(f"[*] Kill all {GOOMBA_KILLS} Goombas and {KOOPA_KILLS} Koopa to see the flag!")

    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python keygen.py <original_license> <your_fingerprint>")
        print("\nTo get your fingerprint, reverse the fingerprint collection")
        print("logic or extract it from a debug build.")
        sys.exit(1)

    generate_license(sys.argv[1], sys.argv[2])
```

## Getting the Flag

### Step 1: Place License

```bash
$ python keygen.py donor_license.bin "$(cat my_fingerprint.txt)"
[*] Mario Crackme Keygen
==================================================================
[+] HMAC verification: PASSED
[+] Processing crash entanglement...
[+] Processing physics entanglement...
[✓] License generated: .game_license
```

### Step 2: Run the Game

```bash
$ ./mario
```

The game starts without crashing!

### Step 3: Complete Level 1-1

- Navigate through the level
- **Kill ALL 16 Goombas** (stomp them)
- **Kill the 1 Koopa** (stomp it)
- Reach the flagpole and slide down

### Step 4: View the Flag

Upon completing the level with all enemies killed, a special screen displays:

```
FLAG: nite{...}
```

The flag is rendered using two colors:
- **Green tiles** — First half (unlocked at victory)
- **Cyan tiles** — Second half (unlocked at pole slide)

If you skipped enemies, the tiles render as garbage or don't appear.

