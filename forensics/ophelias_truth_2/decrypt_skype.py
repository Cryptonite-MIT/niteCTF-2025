#!/usr/bin/env python3
from Crypto.Cipher import AES
import binascii
import re
import sys

SKYPE_FILE = "skype.txt"
KEYS_FILE = "potentialkeys.txt"
AES_IV = bytes.fromhex("9b5c9b7e83cdfbdf11f87195c3192a47")  # 16 bytes


def extract_username_hex():
    with open(SKYPE_FILE, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    m = re.search(r'"Username"\s*=\s*"(.*?)"', text, re.IGNORECASE)
    if not m:
        m = re.search(r'Username[^0-9a-fA-F]*([0-9a-fA-F]+)', text, re.IGNORECASE)
    if not m:
        raise ValueError("Username value not found")

    hex_str = re.sub(r'[^0-9a-fA-F]', '', m.group(1))
    if len(hex_str) % 2:
        hex_str = hex_str[:-1]
    return hex_str.lower()


def load_keys():
    keys = []
    with open(KEYS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = re.sub(r'[^0-9a-fA-F]', '', line.strip())
            if len(line) >= 64:              # need 32 bytes for AES‑256
                keys.append(bytes.fromhex(line[:64]))
    return keys


def main():
    username_hex = extract_username_hex()
    ct_full = binascii.unhexlify(username_hex)

    # truncate to multiple of 16 bytes
    ct = ct_full[: len(ct_full) - (len(ct_full) % 16)]
    if not ct:
        print("ciphertext too short")
        sys.exit(1)

    keys = load_keys()
    if not keys:
        print("no 256‑bit keys in potentialkeys.txt")
        sys.exit(1)

    print(f"ciphertext: {len(ct)} bytes, keys: {len(keys)}")

    for key in keys:
        try:
            cipher = AES.new(key, AES.MODE_CBC, AES_IV)
            pt = cipher.decrypt(ct)
            if pt.startswith(b"MZ"):
                print("FOUND AES‑256 KEY:", key.hex())
                return
        except Exception:
            continue

    print("no key produced MZ header")


if __name__ == "__main__":
    main()
