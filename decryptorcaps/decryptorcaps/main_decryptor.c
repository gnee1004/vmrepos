#include <windows.h>
#include <stdio.h>
#include "decryptor.h"

#define AES_KEY_SIZE 32
#define IV_SIZE 16
#define IDC_BTN_DECRYPT 1003

HINSTANCE hInst;

// ��ȣȭ �Լ�
void do_decrypt(HWND hwnd) {
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[IV_SIZE];

    restore_key(aes_key);
    restore_iv(iv);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("*.adr", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        int success = 0;
        do {
            if (decrypt_file(fd.cFileName, aes_key, iv)) {
                success++;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);

        if (success > 0) {
            MessageBoxA(hwnd, "��ȣȭ �Ϸ�!", "����", MB_ICONINFORMATION);

            // ������Ʈ â �ݱ� �� encryptor.exe ����
            HWND ransomWnd = FindWindowA("RansomNoteWindow", NULL);
            if (ransomWnd) {
                DWORD pid = 0;
                GetWindowThreadProcessId(ransomWnd, &pid);
                if (pid != 0) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (hProc) {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                    }
                }
            }

        }
        else {
            MessageBoxA(hwnd, "��ȣȭ ����!", "����", MB_ICONERROR);
        }
    }
    else {
        MessageBoxA(hwnd, "��ȣȭ�� .adr ������ �����ϴ�.", "����", MB_ICONERROR);
    }
}

// ������ ���ν���
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateWindowA("static", "�� ��ư�� ���� ��ȣȭ�� �����ϼ���", WS_VISIBLE | WS_CHILD,
            140, 30, 300, 20, hwnd, NULL, hInst, NULL);
        CreateWindowA("button", "��ȣȭ ����", WS_VISIBLE | WS_CHILD,
            180, 70, 120, 30, hwnd, (HMENU)IDC_BTN_DECRYPT, hInst, NULL);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_BTN_DECRYPT)
            do_decrypt(hwnd);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// WinMain ������
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;

    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "DecryptorWindow";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA(
        "DecryptorWindow", "��ȣȭ ���α׷�",
        WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME),
        CW_USEDEFAULT, CW_USEDEFAULT, 480, 180,
        NULL, NULL, hInstance, NULL);

    if (!hwnd) return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
