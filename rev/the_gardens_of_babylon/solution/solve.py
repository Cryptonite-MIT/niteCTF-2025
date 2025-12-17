def u64(x):
    return x & 0xFFFFFFFFFFFFFFFF

TARGET_EPOCH = 0xBAD00600  # 3134440960

# When time == TARGET_EPOCH, t starts as 0 after XOR
def derive_temporal_seed(current_time):
    t = current_time ^ TARGET_EPOCH
    t = u64(t * 0x9C6B4E8A3F7D2B15)
    t ^= (t >> 33)
    t = u64(t * 0x4F2E9A7C6D1B8E3A)
    t ^= (t >> 29)
    t = u64(t * 0xB7D4F1A8C3E6925D)
    t ^= (t >> 31)
    t = u64(t * 0x5A8D2E9F4C6B1A73)
    t ^= (t >> 27)
    t = u64(t + 0x7E4A9C2F)
    t ^= (t >> 25)
    t = u64(t * 0x94D049BB133111EB)
    return t ^ (t >> 23)

def prng_next(state):
    state = u64(state + 0x9e3779b97f4a7c15)
    z = u64((state ^ (state >> 30)) * 0xbf58476d1ce4e5b9)
    z = u64((z ^ (z >> 27)) * 0x94d049bb133111eb)
    return state, z ^ (z >> 31)

encrypted = bytes([
    0xeb, 0xda, 0xf9, 0xe9, 0x13, 0x7e, 0xb3, 0x24,
    0x83, 0x19, 0x17, 0xb9, 0xc1, 0x21, 0xae, 0xab,
    0xe4, 0x2a, 0x85, 0xf8, 0xa0, 0x3f, 0xed, 0x44,
    0xf0, 0xe2, 0x59, 0x84, 0xfd, 0x67, 0xd6, 0xfc,
    0xd8, 0xce, 0xea, 0xa2, 0x86, 0x1e, 0xa8, 0x37
])

# Use TARGET_EPOCH as the timestamp
seed = derive_temporal_seed(TARGET_EPOCH)
state = seed
result = []

for i in range(40):
    state, output = prng_next(state)
    result.append(encrypted[i] ^ (output & 0xFF))

print("nite{" + bytes(result).decode() + "}")