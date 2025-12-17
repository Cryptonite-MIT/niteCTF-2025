# Ophelia's Truth 2

> Our initial analysis suggests that the attacker executed a dropper on the victim's machine via RCE, but the executable shows signs of partial corruption, affecting its tailing ends. The malware appears to have deployed an additional executable on the system. Find out:
> - The name of the dropped executable.
> - The paths where the encrypted original malware (dropper) is stored currently.
> - The key used to decrypt and execute the original malware.
>
> Flag format: nite{dropped.exe_SOME\EXAMPLE\Path\1_SOME\EXAMPLE\Path\2_SOME\EXAMPLE\Path\3_keyinhex}

**Author:** Indrath

**Flag:** `nite{RuntimeBroker.exe_HKEY_CURRENT_USER\SOFTWARE\Skype\Username_HKEY_CURRENT_USER\SOFTWARE\Skype\LastProfile_HKEY_CURRENT_USER\SOFTWARE\Skype\SkypePath_90b2cca7c0631aeda7ab1221c98fb1803a6dce2808efdd99e94f5e7cad3a4e78}`

Now as the description mentions that the dropper dropped a executable onto the system, we can start looking for executables on the victims system and look for inconsistencies.

After some searching you will find that a `RuntimeBroker.exe` is located at `\Users\Igor\AppData\Local\Temp\RuntimeBroker.exe`. RuntimeBroker is a system executable and is only present at `\Windows\System32\`. Now we dump the executable for further analysis.

```bash
python vol.py -f ophelia.raw windows.dumpfiles.DumpFiles --virtaddr=0xc201a7024e20
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

ImageSectionObject      0xc201a7024e20  RuntimeBroker.exe       file.0xc201a7024e20.0xc2019fddaa20.ImageSectionObject.RuntimeBroker.exe.img
```

Decompiling and analysing the dumped exe will tell us the following:
- All of the paths and strings are obfuscated with the XOR key `0xCAFEBABE`.

- It retrieves strings from three specific values: `Username`, `LastProfile`, and `SkypePath`. These strings are are then concatenated together.

- Then searches for files in the user's `%TEMP%` directory with the pattern `wct*.tmp`. It then checks if the size of the file equals `64` bytes. This is a strong indicator that the file contains a hex-encoded 256-bit key.

- Once the key is read from the temp file, the malware AES-256-CBC decrypts the concated registry string. The IV is not read from a file but is hardcoded. It is stored as an obfuscated byte array. The IV happens to be `9b5c9b7e83cdfbdf11f87195c3192a47`

- After successful decryption, the malware generates a pseudo-random filename beginning with `WUDFHost_` (mimicking the Windows User-mode Driver Framework Host) and ending with `.exe`. It writes the decrypted bytes to this file in the `%TEMP%` directory and immediately executes it.

This represents a multi-stage infection where the first stage encrypts and hides itself, while this second stage (RuntimeBroker.exe) acts as the loader that reconstructs and executes the original malware.

The original malware paths reconstruct to - `HKEY_CURRENT_USER\SOFTWARE\Skype\Username`, `HKEY_CURRENT_USER\SOFTWARE\Skype\LastProfile` and `HKEY_CURRENT_USER\SOFTWARE\Skype\SkypePath`

Now to get the key, you can `filescan` for files that have `wct` in their name:

```bash
python vol.py -f ophelia.raw windows.filescan.FileScan | grep wct

0xc201a5c8ba40.0\Users\Igor\AppData\Local\Temp\wct8774.tmp
0xc201a702fd20  \Users\Igor\AppData\Local\Temp\wct3550.tmp
```

But dumping them wont work. We need to find an alternative, we know for a fact that the original dropper saved the key in one of these files which the dropped exe uses, so its definite that the key is somewhere in the memory its just that volatility has failed to map the contents of the file to the key files address. So instead one needs to look for strings that are 64 bytes in length via strings.

The dump contains a large number of 64‑byte strings, so identifying the correct key requires generating a wordlist of all potential candidates. Each key should be tested with the known IV to decrypt the Skype registry data. If we look at the description, it mentions that the executable is corrupted at its later sections. But since AES is a block cipher, we can still recover the correct key by decrypting just the initial blocks and checking for the ‘MZ’ signature.

The key which decrypts all the registries successfuly to give an executable is the correct key.

```
python vol.py -f ophelia.raw windows.registry.printkey --key "Software\\Skype" > skype.txt
```
We can write a [python script](decrypt_skype.py) to decrypt the registries (we can just focus on the first registry `Username` and look for the MZ bytes).
```bash
ciphertext: 1668096 bytes, keys: 1253
FOUND AES‑256 KEY: 90b2cca7c0631aeda7ab1221c98fb1803a6dce2808efdd99e94f5e7cad3a4e78
```

The list of potential keys is here: [potentialkeys.txt](potentialkeys.txt)

Hence, the final flag is: `nite{RuntimeBroker.exe_HKEY_CURRENT_USER\SOFTWARE\Skype\Username_HKEY_CURRENT_USER\SOFTWARE\Skype\LastProfile_HKEY_CURRENT_USER\SOFTWARE\Skype\SkypePath_90b2cca7c0631aeda7ab1221c98fb1803a6dce2808efdd99e94f5e7cad3a4e78}`

Another valid flag is: `nite{RuntimeBroker.exe_HKCU\SOFTWARE\Skype\Username_HKCU\SOFTWARE\Skype\LastProfile_HKCU\SOFTWARE\Skype\SkypePath_90b2cca7c0631aeda7ab1221c98fb1803a6dce2808efdd99e94f5e7cad3a4e78}`

Challenge Source Code:

- [RuntimeBroker.exe Source](RuntimeBroker.cpp)

