import itertools
import string
import binascii
import time
from Crypto.Hash import keccak

# --- CONFIGURATION ---
# The hashes extracted from the contract
TARGET_HASHES = [
    "0xf59964cd0c25442208c8d0135bf938cf10dee456234ac55bccafac25e7f16234",
    "0xa12f9f56c9d0067235de6a2fd821977bacc4d5ed6a9d9f7e38d643143f855688",
    "0x3486d083d2655b16f836dcf07114c4a738727c9481b620cdf2db59cd5acfe372",
    "0x2dfb14ffa4d2fe750d6e28014c3013793b22e122190a335a308f0d330143da3d",
    "0xd62d22652789151588d2d49bcd0d20a41e2ba09f319f6cf84bc712ea45a215ef",
    "0x6cf18571f33a226462303a6ae09be5de3c725b724bf623b5691dcb60651ee136",
    "0x2b86ca86c8cfc8aa383afc78aa91ab265b174071d300c720e178264d2f647a42",
    "0xe9d5b7877c45245ca46dc5975dc6b577baa951b05f59a8e7b87468bfad4a956d"
]

# The salt (Contract Owner Address)
OWNER_ADDRESS = "0x1597126b98A9560cA91Ad4b926D0dEF7E2c45603"

# Search Space: Lowercase, Uppercase, Digits, Symbols
CHARSET = string.ascii_letters + string.digits + "{}_$%!@&"
MAX_LEN = 4  # We know the chunk size is 4

def get_hash(candidate_str, owner_bytes):
    """
    Simulates keccak256(abi.encodePacked(bytes32(candidate), owner))
    """
    # 1. Pad string to 32 bytes (Solidity bytes32 logic)
    candidate_bytes = candidate_str.encode('utf-8')
    p_bytes32 = candidate_bytes.ljust(32, b'\0')
    
    # 2. Concatenate with owner bytes
    packed = p_bytes32 + owner_bytes
    
    # 3. Hash
    k = keccak.new(digest_bits=256)
    k.update(packed)
    return "0x" + k.hexdigest()

def solve_chunk(target_hash, owner_bytes):
    """Brute forces a single chunk hash."""
    for length in range(1, MAX_LEN + 1):
        # Generate all combinations (e.g., 'a', 'b', ... 'aa', 'ab'...)
        for p in itertools.product(CHARSET, repeat=length):
            candidate = "".join(p)
            
            if get_hash(candidate, owner_bytes) == target_hash:
                return candidate
    return None

def main():
    print(f"[*] Starting Brute Force on {len(TARGET_HASHES)} chunks...")
    print(f"[*] Salt (Owner): {OWNER_ADDRESS}")
    print(f"[*] Max Chunk Length: {MAX_LEN}")
    print("-" * 50)

    # Pre-process owner address
    clean_addr = OWNER_ADDRESS.replace("0x", "")
    owner_bytes = binascii.unhexlify(clean_addr)
    
    flag_parts = []
    start_time = time.time()

    for i, h in enumerate(TARGET_HASHES):
        print(f"Cracking Chunk #{i+1}...", end=" ", flush=True)
        
        result = solve_chunk(h, owner_bytes)
        
        if result:
            print(f"FOUND: '{result}'")
            flag_parts.append(result)
        else:
            print("FAILED. (Increase MAX_LEN or check charset)")
            return

    total_time = time.time() - start_time
    full_flag = "".join(flag_parts)
    
    print("-" * 50)
    print(f"[SUCCESS] Flag Reconstructed in {total_time:.2f}s:")
    print(f"\n    {full_flag}\n")
    print("-" * 50)

if __name__ == "__main__":
    main()
