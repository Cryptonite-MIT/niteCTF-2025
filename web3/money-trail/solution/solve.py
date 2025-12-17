import requests
import time
from collections import deque
import sys

API_URL = "https://evm-testnet.flowscan.io/api"
START_ADDRESS = "0xfb1e691adac8361ba054626733bc4b701568da8a"
MAX_RETRIES = 5

def fetch_transactions(address):
    params = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "sort": "asc"
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(API_URL, params=params, timeout=10)
            
            if response.status_code == 429:
                wait_time = 2 ** attempt
                print(f"[!] Rate limited. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
                
            if response.status_code != 200:
                print(f"[!] HTTP {response.status_code} for {address}")
                return None

            data = response.json()
            
            if data.get("status") == "1" and data.get("result"):
                return data["result"]
            elif data.get("message") == "No transactions found":
                return []
            else:
                return []
                
        except requests.RequestException as e:
            print(f"[!] Request error: {e}. Retrying...")
            time.sleep(2 ** attempt)
            
    print(f"[x] Failed to fetch transactions for {address} after {MAX_RETRIES} attempts.")
    return None

def solve():
    queue = deque([START_ADDRESS])
    visited = set()
    contract_calls = []
    
    print(f"[*] Starting trace from: {START_ADDRESS}")
    
    while queue:
        current_addr = queue.popleft().lower()
        
        if current_addr in visited:
            continue
        visited.add(current_addr)
        
        if len(visited) % 25 == 0:
            print(f"[*] Progress: Visited {len(visited)} addresses | Queue size: {len(queue)}")

        txs = fetch_transactions(current_addr)
        if txs is None:
            continue
            
        for tx in txs:
            sender = tx.get("from", "").lower()
            receiver = tx.get("to", "").lower() if tx.get("to") else None
            input_data = tx.get("input", "0x")
            
            if sender != current_addr:
                continue

            if input_data and input_data != "0x":
                print(f"\n[+] Suspicious transaction found!")
                print(f"    Hash: {tx['hash']}")
                print(f"    Input: {input_data}")
                contract_calls.append(tx)
                
                try:
                    decoded = bytes.fromhex(input_data[2:]).decode('utf-8')
                    print(f"    Decoded Flag: {decoded}")
                    if "nite{" in decoded:
                        print("\n" + "="*40)
                        print(f"FLAG ACQUIRED: {decoded}")
                        print("="*40)
                        return
                except Exception:
                    print("    (Could not decode as plain ASCII)")

            if receiver and receiver not in visited:
                queue.append(receiver)

    print("[*] Crawl finished.")

if __name__ == "__main__":
    solve()
