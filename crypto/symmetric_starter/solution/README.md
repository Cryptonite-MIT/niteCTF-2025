# symmetric starter Solution

**Flag:** `nite{wh00ps_l34k3d_2_mUch}`

1. The key idea is to realise that the `shifts` actually leak quite a bit about the nonce, and since there are enough blocks, the nonce can be reconstructed just from using the shifts i.e. leak i.e. MSB of the nonce.
2. Since the nonce itself is derived from the key, the key can be found using the leaks by using Z3 to model initial nonce as 16 symbolic 8 bit variables.
3. Once satisfied, the AES key is used to reverse the encryption and the decrypt function retrieves the original message.
4. The flag can be found in the decrypted message using regex.

[Solve script](solve.py)

```
key bytes: bytearray(b'\x01H\xa6rT\x80A\xe2\\\x87\xea9}?Zp')
key hex: 0148a672548041e25c87ea397d3f5a70
flag: nite{wh00ps_l34k3d_2_mUch}
```
