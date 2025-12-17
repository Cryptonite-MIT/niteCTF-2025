import hashlib
import random
import os

class Lottery:
    def __init__(self):
        self.hash_funcs = [hashlib.sha256]*1024+[hashlib.sha3_224]*1023+[hashlib.sha1]
        self.shuffled = False
        self.secret = os.urandom(16).hex()

    def buy_ticket(self,pay, username):
        
        if not self.shuffled:
            random.shuffle(self.hash_funcs)
            self.shuffled = True

        ticket_id = random.randint(1, 11)
        hash_idx = random.randint(0, len(self.hash_funcs) - 1)
        if pay == 0:
            print('Hey you cannot pay nothing!\n')
            return False
        
        if ticket_id > 5:
            amount = random.randint(1, 10)
            print(f"Ticket #{ticket_id}: You won! ${amount}")
            
            hash_func = self.hash_funcs[hash_idx]
            ticket_data = f"{username}|{amount}"
            ticket_hash = hash_func((self.secret + ticket_data).encode()).digest()[:20]
            ticket_voucher = ticket_hash.hex()
            
            print('Voucher data: ',ticket_data.encode().hex())
            print('Voucher code: ',ticket_voucher,'\n')
            return True
        else:
            print("You lost!\n")
            return True
    
    def redeem_voucher(self, voucher_code, voucher_data):
        
        try:
            voucher_bytes = bytes.fromhex(voucher_code)
            if len(voucher_bytes) != 20:
                print("Invalid voucher code")
                return 0
        except:
            print("Invalid voucher code format")
            return 0
        
        data_bytes = bytes.fromhex(voucher_data)

        for hash_func in [hashlib.sha256, hashlib.sha3_224, hashlib.sha1]:
            message = self.secret.encode() + data_bytes
            computed_hash = hash_func(message).digest()[:20]
            
            if computed_hash == voucher_bytes:
                try:
                    data_str = data_bytes.decode('latin-1')  
                    parts = data_str.split('|')
                    amount = None
                    for part in reversed(parts):
                        try:
                            amount = int(part)
                            break
                        except ValueError:
                            continue
                    
                    if amount is None:
                        print("Could not parse amount")
                        return 0
                    
                    print(f"Voucher redeemed: ${amount}")
                    return amount
                    
                except:
                    print("Could not parse voucher data")
                    return 0
        
        print("Invalid voucher")
        return 0