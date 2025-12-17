# Quick Mistake

> Our internal service recently reported abnormal and inconsistent behavior. It is suspected that our network might have been compromised. It is also suspected that the attacker may have used the admin telemetry to their advantage. A packet capture taken during the incident window has been provided. Figure out what has been compromised and what internal data the attacker gained access to.

**Author:** `kafka`

**Flag:** `nite{192.0.2.66_2457ce19cb87e0eb_qu1c_d4t4gr4m_pwn3d}`.

**Handout:** [Chal.pcap](./Chal.pcap)

- Open `challenge.pcap` in Wireshark.
- Filter for `quic`.
- Identify three IPs:
    - Legit Client: `198.51.100.10` (First to connect).
    - Attacker: `192.0.2.66` (Reuses Legit Client's SCID).
    - Admin Bot: `198.51.100.5` (Connects separately).
    - Server: `203.0.113.100` (Responds to all).

- Use the following tshark command to get all the scid used:
```sh
tshark -r challenge.pcap -Y "quic.long.packet_type == 0" -T fields -e frame.time_relative -e ip.src -e quic.scid
```

Attacker SCID is `2457ce19cb87e0eb`

- The admin bot while connecting to the server is also leaking critical information that could be find out in `packet 179`

```json
{"type": "handshake_init", "seed": "af717e2c8789db71fe624598faba3953c23fdb685e6b8cd2e6f84beef0c57175", "salt": "telemetry", "info": "sslkeylog"}
```
- Further we also get information about something called `telemetry_sslkeylog` :

```json
{"type": "telemetry_sslkeylog", "seq": 0, "total_chunks": 2, "nonce_b64": "S459VmTWtpNcz+NU", "ct_b64": "D4Y706RkRpgzXAOAWe4eKyE3AjfFXxOgxXGV7SsKeH4umYbfaY6VMedKeghapSgIyghK7rLSJxwRWwDREt1sN+ZV3MPnw4CdaqOWdh3o3dLtlyJSsDg9iYYAynV68VaXKQna5xFGaFr9x0b3vuvbFTJ7u3zgTlAmpEutj0F4leuLZDGRZupvr9+jyNLxnGNVxNXwLTcYSIR1iTOUdao/252x4H9c7DjCeuvCDX4hYfPv+l5g8JEuwutqCbdzn3nVkL4s0931lT8wpkV4suIR+0bV+X4SU8pd6XlrkxweEWpVIbJkhqnKh5driyqA/1TneBVZKS03k7TiX9ZXqmVhS4r3BKrk7wMnVwQLSLmC07UOvIEsqzWp0GJnYvyGV1FzB7Tw4JXakoLhOGs+ocpGr2PuhSrUTiAW465ikw3+lsEnKI/OFG7I+2nVjKkBA09bu17iJHNoOD3rmQ0cRGiJ8/Vr3YufXeQDMn/REyoG+Wnv/P5rR1I/O6qn/5LHiWSqaNWpg7jjRvU/pt4KBPMMTckeXTseYUwts0Ntk7IBBztYnmq1zZSNhdAZ+KQQ1/8I/lJVdgg5YWZSdepexZVJuiofPgYN55fnvWqK/LxmVE4D3gOKKbJWCQoL1FgadmZ4iX99MjYzs2qsOp9m8i1yvrMbQ4emX7hjjk74I5rfZ9E+01bBvLiw4smdlBiT4ztWA/uQPYqZC/kN06Fu9LTYTCGR8/B/4mAlKUh6ZzQDePGrYiuR0k5/WRH2fzcYnUAt5NOt6akHE3ljXOW28PV2G5IL94IxPYkITHNPTMp2J84QcuozCHtf9ex/b3fG+DLPXT0zrxh5j11SsCTULPUmLXKKqCXc/NHaxHrquM7PUZi5fQZ7Jmz386K+2ExR4ycTNVSB2MuPDzvG+FPQP60M6varPywdWM6lM7IrDQ02lXC7/n9o+m60uIjfI52IvDe4b2NFJQeU2dFPKkAX1N68yWGc75IVz2noScPqaq4P978sT+z9DfKOe0ifQc0So8qoi2WHKvB5bEUjFezszGhWzq7rJ7toUu5rg+t5i9Tuf/qpFZfcwBHyPr8o6bmkLj0p9IsEldTKUZiD4Ng8ReYn9pwwc6weeZ02D432ziDSxwIB5NA/32GV50hT+4EvTeo1cCyyGxT9Na+Qd3RVoJgO4TDWTLYwVI/x2cFa88WbAjMHveWGGiEK5TZD3Ad2Jkj3UmTj0ETTuzW1aTqTHEfVY+7A/XTNN3E1Q4VB2+e+p2JxybXgvYSmhX0aQuzmqwXhRmA8BnpBBvwl/99rKQLdJUPnnrre06Om8Azi81212PaQtiq+IEuMWg==", "tag_b64": "ElHxGRAt7wicOe+lFkLiaw=="}
```

```json
{"type": "telemetry_sslkeylog", "seq": 1, "total_chunks": 2, "nonce_b64": "tXd5ku7fU1lPn/D9", "ct_b64": "o6vvBmgm6Iyj9/RRUjDdqtcFj6tn4E/7whY/4do67UD3NgRHqicb3eWZ+O8xvMaok+MHjhRreah9QQS1NEy+fAbDGMhqVqwqeNS6F5j+MOv7UX7N1wn2ZyaIxT2UogGb6D2c+F7rnaJZdpsrDQ/ZEwQTaJVuHGNTQM1klV+UZOUJ4mZzSp+/u8M1p/JJrDcMjzaGypiP7HrZ+g6FGkL83PCzWKGSVw/3syZtuzu65Owtk5XbYqDRn7MN1rYeuCzoYlSoQ3ZccUQkk9+U4BTfgImBlBqT3D3byVxqMuz5JR6MyK/AGkUXpn2qaBtX00rEtKhnJ7iLRkkBVeXbUd/rWqUfGpf6QpOEiVQeA17p80mw5g68X52u03388XhfIbfR/qehWE7wK/t8O90/CiTNvCrhFgNg5Kvze/zgDz0lJ2h3sCoThsUjP6m3lXV6rYFnswLr6fmvD26tU3+wrmSvdBbHfaLovLmmBtI9bjDw44vpgNQ4HxttPiPllYZXZYvhTrs7P4XDDqDGRHwiHn0AmDR79UVrVO0ie5RsQt91wMT+3OhxiScRiH+xw7RpTd6wb3SLNcNwVQSc+zm3ZLBv8cNGj6TknRhbcSkZxmK7yANX3FcorjuGJDd+5kSzzOihuEw8qXVLXI0XLHtL7wz7nWDP8bKLIYvOVRd59aRnOuuH9dCD4Zc5", "tag_b64": "ZlYYx1K6YiALxD0Tm9k6/w=="}
```
- Figure out its **AEAD (AES-GCM) encrypted structure** and the `seed`, `salt` and `info` leaked earlier could be helpful in decrypting it.

- Use `solve_decrypt.py` to get `recovered_sslkeylog.txt`

- Wireshark -> Preferences -> Protocols -> TLS.
- Set "(Pre)-Master-Secret log filename" to `recovered_sslkeylog.txt`.
- Reload PCAP. HTTP/3 traffic should now be decrypted.
- Filter for `http3`.
- Find the attacker request to `/source`
- Figure out the data sent is in form of `tar.gz` from the decrypted
- extract the tar.gz and in the .env
- Get the `AES secret key` `AES_FLAG_KEY=wEN64tLF1PtOglz3Oorl7su8_GQzmlU2jbFP70cFz7c=` from the .env file
- Decrypt the flag using the AES key and the /flag

```
gAAAAABpNXDCHUJ4YqH0Md2p6tzE303L8z5kPpPPWwYYrXUdiyW89eCaWWL1dbYU2JYj7SUvdwySW_egZDRF0fyFGxPua2KoFmd8upKP7cZv55jVp_SzItA=
^^^^^^
Fernet encryption header
```

using the below script:

```py
from cryptography.fernet import Fernet, InvalidToken

KEY = b"wEN64tLF1PtOglz3Oorl7su8_GQzmlU2jbFP70cFz7c="
TOKEN = b"gAAAAABpNXDCHUJ4YqH0Md2p6tzE303L8z5kPpPPWwYYrXUdiyW89eCaWWL1dbYU2JYj7SUvdwySW_egZDRF0fyFGxPua2KoFmd8upKP7cZv55jVp_SzItA="

def main():
    f = Fernet(KEY)
    try:
        pt = f.decrypt(TOKEN)
        try:
            print(pt.decode("utf-8"))
        except:
            print(pt)
    except InvalidToken:
        print("Invalid key or token.")

if __name__ == "__main__":
    main()

```

