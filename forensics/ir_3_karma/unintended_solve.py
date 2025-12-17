import hashlib
from Crypto.Cipher import AES
import sys

# ================= CONFIGURATION =================
# The encrypted file path
ENCRYPTED_FILE = "secret.png.enc"

# The fixed parts of the string
PREFIX = "6.2.9200"
SUFFIX = "ANAKT"

# We don't know the IV, so we use 16 null bytes.
# If the key is correct, this will result in a garbage 1st block
# but valid 2nd, 3rd, etc. blocks.
IV = b'\x00' * 16
# =================================================

def generate_dates():
    """Generates the SUASUASUA + month + day wordlist."""
    months = {
        "january": 31, "february": 29, "march": 31, "april": 30,
        "may": 31, "june": 30, "july": 31, "august": 31,
        "september": 30, "october": 31, "november": 30, "december": 31
    }
    base = "SUASUASUA"
    wordlist = []
    for month, days in months.items():
        for day in range(1, days + 1):
            wordlist.append(f"{base}{month}{day}")
    return wordlist

def is_png_likely(data):
    """
    Checks if the decrypted data looks like a PNG.
    Since the first block (Header) might be corrupt due to bad IV,
    we scan for 'IDAT' (Image Data) or 'IEND' chunks.
    """
    # Quick check for standard markers
    if b'IDAT' in data or b'IEND' in data:
        return True

    # Optional: Check for IHDR if it survived (unlikely if IV is wrong)
    if b'IHDR' in data:

        return True

    return False

def run_bruteforce():
    try:
        # Read enough bytes to likely capture an IDAT chunk (e.g., first 4KB)
        with open(ENCRYPTED_FILE, "rb") as f:
            encrypted_data = f.read(4096)
    except FileNotFoundError:
        print(f"Error: Could not find file '{ENCRYPTED_FILE}'")
        return

    candidates = generate_dates()
    print(f"[*] Loaded {len(candidates)} passwords to test...")
    print(f"[*] Testing format: {PREFIX}<word>{SUFFIX}")

    for word in candidates:
        # Construct the candidate string
        candidate_str = f"{PREFIX}{word}{SUFFIX}"

        # Test 1: ASCII Encoding
        key_ascii = hashlib.md5(candidate_str.encode('ascii')).digest()
        cipher_ascii = AES.new(key_ascii, AES.MODE_CBC, IV)
        decrypted_ascii = cipher_ascii.decrypt(encrypted_data)

        if is_png_likely(decrypted_ascii):
            print("\n[+] FOUND KEY (ASCII)!")
            print(f"    String: {candidate_str}")
            print(f"    Key:    {key_ascii.hex()}")
            return

        # Test 2: UTF-16LE Encoding (Windows Unicode standard)
        # Many Windows APIs (GetVersionExW, GetComputerNameW) return Unicode
        key_unicode = hashlib.md5(candidate_str.encode()).digest()
        cipher_unicode = AES.new(key_unicode, AES.MODE_CBC, IV)
        decrypted_unicode = cipher_unicode.decrypt(encrypted_data)
        print(decrypted_unicode[16:64])

    print("\n[-] Bruteforce finished. No valid PNG structure found.")
    print("    Check: 1. Is 'secret.png' actually encrypted?")
    print("           2. Are the prefix/suffix correct?")
    print("           3. Try adding a null terminator to the string logic.")

if __name__ == "__main__":
    run_bruteforce()
