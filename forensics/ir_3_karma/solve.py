import base64
import hashlib
from pathlib import Path
from urllib.request import urlopen
from scapy.all import rdpcap, TCP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def get_iv():
    return hashlib.md5(b'nite{1nsp1r3d_by_he_H3_xD_xqvylj8rtap8}').digest()

def get_key():
    return hashlib.md5(("6.2.9200" + "SUASUASUAdecember22" + "ANAKT").encode("utf-8")).digest()

def extract_payload(pcap_path, port):
    chunks = []
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if TCP not in pkt:
            continue
        tcp = pkt[TCP]
        if tcp.dport != port and tcp.sport != port:
            continue
        payload = bytes(tcp.payload)
        if not payload:
            continue
        chunks.append(payload)
    return b"".join(chunks)

def decrypt_capture():
    ciphertext = extract_payload("capture.pcapng", 1338)
    key = get_key()
    iv = get_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(plaintext, AES.block_size)
    except ValueError:
        pass
    Path("secret.png").write_bytes(plaintext)

if __name__ == "__main__":
    decrypt_capture()

