# Hash Vegas

**Flag:** `nite{9ty%_0f_g4mbler5_qu17_b3f0re_th3y_mak3_1t_big}`

To get the flag, we need to increase our balance to above 1 billion. We can gain some money by playing the slot machine, roulette or redeeming lottery tickets but the amount of money you get will not amount to what we require.

In the lottery class, if you win the lottery(there is a 50% chance), it generates a ticket with a random hash function between `sha256`,`sha3_224` and `sha1` and truncated to 20 bytes. A ticket is of the form `secret|username|amount`. This is vulnerable to length extension attack but the only hash function used here where it can be done is `sha1` which has a probability of 1/2048. If you win a lottery, your balance is set to zero so it can be done only once. You can pay zero dollars for the lottery ticket to progress the random state until `sha1` is used.

```python
self.hash_funcs = [hashlib.sha256]*1024+[hashlib.sha3_224]*1023+[hashlib.sha1]
```
```python
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
```

But to predict when `sha1` is used the random state must be recovered which can be done using the slot machine and roulette.

The slot machine uses `random.choices()` to choose a random 32 bit number, which internally uses `_randbelow()` which by default uses `getrandbits()`.

```python
def _randbelow_with_getrandbits(self, n):
    "Return a random int in the range [0,n).  Defined for n > 0."

    getrandbits = self.getrandbits
    k = n.bit_length()
    r = getrandbits(k)  # 0 <= r < 2**k
    while r >= n:
        r = getrandbits(k)
    return r
```

It generates a `k` bit number(32 in this case) until it is less than the max number of choices. Here the number of choices starts at `2^32-1`. It decreases by `10000` in each iteration but since this is still very close to `2^32`, the probability of it needing multiple `getrandbits()` calls is very low.

Therefore for the most part, `random.choice(self.slots)` behaves the same as `getrandbits(32)`.

Each time you spin the slot machine, 2 32-bit numbers are generated, so 64 bits can be extracted from the slots.

To recover the mersenne state with we need 624 32-bit numbers(19968 bits), since we have 56 rounds of the slot machine we can recover 3584 consecutive bits from `getrandbits()`.
```python
def emoji2val(e):
    val = ''
    for i in e:
        val = bin(emojis.index(i))[2:].zfill(4) + val
    return int(val,2)

def get_slotval(no=False):
    r.recvuntil(b'Enter your choice: ')
    r.sendline(b'1')
    data = r.recvuntil(b'Updated balance: $').decode('utf-8')
    wheel = ''
    for c in data:
        if c in emojis:
            wheel+=c
    if not no:
        rc.submit(emoji2val(wheel[:8]))
        rc.submit(emoji2val(wheel[8:]))
    print(emoji2val(wheel[8:]))
```

The roulette uses `random.randrange()` which just like `random.choice()` uses `_randbelow()` internally. Since the upper bound of the change is `2^256-1`, the random number generated will pretty much always be below it and only one `getrandbits()` call is use. So using `random.randrange(0,self.n)` we get the output of `getrandbits(256)`.

Since we can play the roulette 64 times, we recover 16384 consecutive bits of `getrandbits()` outputs. This along with the bits we got from the slot machine is enough to recover the mt state.

```python
def submit_256(val):
    for i in range(8):
        shift = i * 32
        part = (val >> shift) & 0xFFFFFFFF
        rc.submit(part)

def get_rouletteval():
    r.recvuntil(b'Enter your choice: ')
    r.sendline(b'2')
    r.sendline(b'1')
    r.sendline(b'R')
    r.recvuntil(b'the number is ')
    num = int(r.recvline().strip().decode())
    r.recvuntil(b'Updated balance: $')
    submit_256(num)
```

Once you recover the mt state, progress the mt state by paying zero for the lottery ticket until `sha1` is used and you would win the lottery.

Then perform length extension attack on the ticket using [hash-length-extention](https://github.com/thecrabsterchief/hash-length-extension) such that you could redeem a billion dollars.

```python
def forge_lottery(username,amount,vcode):
    original_data = (username+'|'+str(amount)).encode()
    append_data = b"|1000000000"
    magic = HashTools.new("sha1")
    new_data, new_code = magic.extension(
        secret_length=32,
        original_data=original_data,
        append_data=append_data,
        signature=vcode
    )
    return new_data,new_code

def get_lottery():
    shuffle(hash_funcs)
    sha1_idx = hash_funcs.index(hashlib.sha1)
    print(sha1_idx)
    found = False
    while not found:
        ticket_id = random.randint(1, 11)
        hash_idx = random.randint(0, len(hash_funcs) - 1)
        if ticket_id > 5 and hash_idx == sha1_idx:
            found = True
            print('found it')
            break
        r.recvuntil(b'Enter your choice: ')
        r.sendline(b'3')
        r.sendline(b'0')
    r.sendline(b'3')
    r.sendline(b'1')

    r.recvuntil(b'won! $')
    amount = int(r.recvline().strip().decode())
    r.recvuntil(b'data: ')
    vdata = r.recvline().strip().decode()
    r.recvuntil(b'code: ')
    vcode = r.recvline().strip().decode()
    return amount,vdata,vcode
```

Redeem the forged ticket to get a billion dollars, then you can access the flag.

[Solve script](solve.py)

