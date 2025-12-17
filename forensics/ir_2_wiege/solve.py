import os
from pathlib import Path

def calculate_hash(data):
    hash_val = 0xbaadf00d

    for byte in data:
        hash_val ^= byte
        hash_val = (hash_val * 0x9e3779b1) & 0xFFFFFFFF
        hash_val ^= hash_val >> 16
        hash_val = (hash_val * 0x85ebca77) & 0xFFFFFFFF
        hash_val ^= hash_val >> 13

    return hash_val & 0xFFFFFF

def decode_string(input_dir):
    folders = []
    for entry in os.listdir(input_dir):
        path = os.path.join(input_dir, entry)
        if os.path.isdir(path):
            folders.append((entry, path))

    folders.sort(key=lambda x: x[0])

    decoded = []

    for folder_name, folder_path in folders:
        files = []
        for file_name in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file_name)
            if os.path.isfile(file_path):
                files.append(file_name)

        files.sort()

        base4_parts = []

        for file_name in files:
            file_path = os.path.join(folder_path, file_name)
            with open(file_path, 'rb') as f:
                data = f.read()

            hash_val = calculate_hash(data)
            pool = hash_val // (0x1000000 // 4)
            base4_parts.append(pool)

        byte_value = 0
        for value in base4_parts:
            byte_value = byte_value * 4 + value

        decoded.append(byte_value)

    return bytes(decoded).decode('utf-8', errors='ignore')

if __name__ == "__main__":
    input_dir = "C:\\Users\\Mizi\\AppData\\Roaming\\Diagnostics\\"
    result = decode_string(input_dir)
    print(result)
