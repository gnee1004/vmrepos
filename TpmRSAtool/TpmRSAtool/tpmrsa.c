/*
 * tpm_rsa_tool.c
 * TPM-backed RSA Encrypt/Decrypt + Key Management (Interactive Mode)
 *
 * Build:
 *   - Console Subsystem
 *   - C11
 *   - Link: ncrypt.lib, bcrypt.lib, advapi32.lib
 *
 * Usage:
 *   실행 후 콘솔에서 명령어 및 파일 경로를 순차적으로 입력받습니다.
 */

#include <windows.h>
#include <ncrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#define HEADER_SIG          "RSAENCv1"
#define HEADER_LEN          8
#define MAX_PLAINTEXT_CHUNK 245  // RSA2048 PKCS#1 v1.5

static const char* encrypt_exts[] = {
    ".doc", ".docx", ".txt", ".xls",
    ".xlsx", ".ppt", ".pptx", ".pdf"
};
static const int num_encrypt_exts = sizeof(encrypt_exts) / sizeof(encrypt_exts[0]);

// 복호화용 확장자: .drm
static int has_encrypt_ext(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return 0;
    for (int i = 0; i < num_encrypt_exts; i++)
        if (_stricmp(ext, encrypt_exts[i]) == 0)
            return 1;
    return 0;
}
static int has_decrypt_ext(const char* path) {
    const char* ext = strstr(path, ".drm");
    return (ext && ext[strlen(ext) - 1] == 'm');
}

static void fail_exit(const char* msg, SECURITY_STATUS st) {
    fprintf(stderr, "%s (0x%lx)\n", msg, st);
    exit(1);
}

static NCRYPT_PROV_HANDLE open_tpm() {
    NCRYPT_PROV_HANDLE hProv;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&hProv,
        MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (st != ERROR_SUCCESS) fail_exit("NCryptOpenStorageProvider failed", st);
    return hProv;
}

static void create_one_key(NCRYPT_PROV_HANDLE hProv, LPCWSTR keyName) {
    NCRYPT_KEY_HANDLE hKey;
    DWORD keyLen = 2048;
    SECURITY_STATUS st = NCryptCreatePersistedKey(
        hProv, &hKey, NCRYPT_RSA_ALGORITHM, keyName,
        0, NCRYPT_OVERWRITE_KEY_FLAG);
    if (st != ERROR_SUCCESS) fail_exit("CreateKey failed", st);
    st = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&keyLen, sizeof(keyLen), 0);
    if (st != ERROR_SUCCESS) fail_exit("SetProperty failed", st);
    st = NCryptFinalizeKey(hKey, 0);
    if (st != ERROR_SUCCESS) fail_exit("FinalizeKey failed", st);
    wprintf(L"[genkey] Created TPM key: %s\n", keyName);
    NCryptFreeObject(hKey);
}

static void cmd_genkey(const wchar_t* id) {
    NCRYPT_PROV_HANDLE hProv = open_tpm();
    // Generate 5 random key names using GUIDs
    for (int i = 1; i <= 5; i++) {
        GUID guid;
        CoCreateGuid(&guid);
        wchar_t guidStr[64];
        swprintf(guidStr, 64, L"%08x-%04x-%04x-%04x-%012llx",
            guid.Data1, guid.Data2, guid.Data3,
            (guid.Data4[0] << 8) | guid.Data4[1],
            *((unsigned long long*)(guid.Data4 + 2)));

        wchar_t name[128];
        swprintf(name, 128, L"tpm_%s_%s", id, guidStr);
        create_one_key(hProv, name);
    }
    NCryptFreeObject(hProv);
}

static void cmd_checkkey(const wchar_t* id) {
    NCRYPT_PROV_HANDLE hProv = open_tpm();
    wchar_t name[128];
    swprintf(name, 128, L"tpm_%s_1", id);
    NCRYPT_KEY_HANDLE hKey;
    SECURITY_STATUS st = NCryptOpenKey(hProv, &hKey, name, 0, 0);
    if (st == ERROR_SUCCESS) {
        wprintf(L"[checkkey] Key exists: %s\n", name);
        NCryptFreeObject(hKey);
    }
    else if (st == NTE_BAD_KEYSET) {
        wprintf(L"[checkkey] Key not found: %s\n", name);
    }
    else fail_exit("NCryptOpenKey failed", st);
    NCryptFreeObject(hProv);
}

static void cmd_deletekey(const wchar_t* id) {
    NCRYPT_PROV_HANDLE hProv = open_tpm();
    for (int i = 1; i <= 5; i++) {
        wchar_t name[128];
        swprintf(name, 128, L"tpm_%s_%d", id, i);
        NCRYPT_KEY_HANDLE hKey;
        SECURITY_STATUS st = NCryptOpenKey(hProv, &hKey, name, 0, 0);
        if (st == ERROR_SUCCESS) {
            st = NCryptDeleteKey(hKey, 0);
            if (st != ERROR_SUCCESS) fail_exit("DeleteKey failed", st);
            wprintf(L"[deletekey] Deleted: %s\n", name);
            NCryptFreeObject(hKey);
        }
        else {
            wprintf(L"[deletekey] Not exist: %s\n", name);
        }
    }
    NCryptFreeObject(hProv);
}

static unsigned char* read_file_all(const char* path, size_t* outLen) {
    FILE* f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); *outLen = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* buf = malloc(*outLen);
    fread(buf, 1, *outLen, f); fclose(f);
    return buf;
}

static void cmd_encrypt(const wchar_t* id, const char* path) {
    if (!has_encrypt_ext(path)) {
        fprintf(stderr, "Error: Unsupported input file extension.\n");
        return;
    }
    size_t inLen; unsigned char* inBuf = read_file_all(path, &inLen);
    if (!inBuf) { perror("Read input failed"); return; }
    NCRYPT_PROV_HANDLE hProv = open_tpm();
    wchar_t name[128]; swprintf(name, 128, L"tpm_%s_1", id);
    NCRYPT_KEY_HANDLE hKey;
    SECURITY_STATUS st = NCryptOpenKey(hProv, &hKey, name, 0, 0);
    if (st != ERROR_SUCCESS) fail_exit("NCryptOpenKey failed", st);
    // Backup (숨김 + 원본 삭제)
    char bak[MAX_PATH]; snprintf(bak, MAX_PATH, "%s.bak", path);
    CopyFileA(path, bak, FALSE);
    SetFileAttributesA(bak, FILE_ATTRIBUTE_HIDDEN);
    DeleteFileA(path);
    printf("[backup] Hidden backup: %s\n", bak);
    // Output .drm 파일 (원본 이름 + ".drm")
    char outPath[MAX_PATH];
    snprintf(outPath, MAX_PATH, "%s.drm", path);
    FILE* out = fopen(outPath, "wb"); if (!out) { perror("Create output failed"); return; }
    // Header
    fwrite(HEADER_SIG, 1, HEADER_LEN, out);
    DWORD chunks = (DWORD)((inLen + MAX_PLAINTEXT_CHUNK - 1) / MAX_PLAINTEXT_CHUNK);
    fwrite(&chunks, sizeof(chunks), 1, out);
    for (DWORD i = 0; i < chunks; i++) {
        DWORD offset = i * MAX_PLAINTEXT_CHUNK;
        DWORD inSz = (DWORD)min((size_t)MAX_PLAINTEXT_CHUNK, inLen - offset);
        DWORD outSz = 0;
        st = NCryptEncrypt(hKey, inBuf + offset, inSz, NULL, NULL, 0, &outSz, NCRYPT_PAD_PKCS1_FLAG);
        if (st != ERROR_SUCCESS) fail_exit("Encrypt size failed", st);
        unsigned char* outBuf = malloc(outSz);
        st = NCryptEncrypt(hKey, inBuf + offset, inSz, NULL, outBuf, outSz, &outSz, NCRYPT_PAD_PKCS1_FLAG);
        if (st != ERROR_SUCCESS) fail_exit("Encrypt data failed", st);
        fwrite(&outSz, sizeof(outSz), 1, out);
        fwrite(outBuf, 1, outSz, out);
        free(outBuf);
    }
    fclose(out); NCryptFreeObject(hKey); NCryptFreeObject(hProv); free(inBuf);
    printf("[encrypt] Done: %s\n", outPath);
}

static void cmd_decrypt(const wchar_t* id, const char* path) {
    if (!has_decrypt_ext(path)) {
        fprintf(stderr, "Error: Input for decryption must have .drm extension.\n");
        return;
    }
    FILE* in = fopen(path, "rb"); if (!in) { perror("Open input failed"); return; }
    char header[HEADER_LEN]; fread(header, 1, HEADER_LEN, in);
    if (memcmp(header, HEADER_SIG, HEADER_LEN) != 0) {
        fprintf(stderr, "Invalid file format\n"); fclose(in); return;
    }
    DWORD chunks; fread(&chunks, sizeof(chunks), 1, in);
    NCRYPT_PROV_HANDLE hProv = open_tpm();
    wchar_t name[128]; swprintf(name, 128, L"tpm_%s_1", id);
    NCRYPT_KEY_HANDLE hKey;
    SECURITY_STATUS st = NCryptOpenKey(hProv, &hKey, name, 0, 0);
    if (st != ERROR_SUCCESS) fail_exit("OpenKey failed", st);
    // Output original filename (path without trailing .drm)
    size_t len = strlen(path) - strlen(".drm");
    char outPath[MAX_PATH];
    memcpy(outPath, path, len);
    outPath[len] = '\0';
    FILE* out = fopen(outPath, "wb"); if (!out) { perror("Create output failed"); fclose(in); return; }
    for (DWORD i = 0; i < chunks; i++) {
        DWORD encSz; fread(&encSz, sizeof(encSz), 1, in);
        unsigned char* encBuf = malloc(encSz); fread(encBuf, 1, encSz, in);
        DWORD decSz = 0;
        st = NCryptDecrypt(hKey, encBuf, encSz, NULL, NULL, 0, &decSz, NCRYPT_PAD_PKCS1_FLAG);
        if (st != ERROR_SUCCESS) fail_exit("Decrypt size failed", st);
        unsigned char* decBuf = malloc(decSz);
        st = NCryptDecrypt(hKey, encBuf, encSz, NULL, decBuf, decSz, &decSz, NCRYPT_PAD_PKCS1_FLAG);
        if (st != ERROR_SUCCESS) fail_exit("Decrypt data failed", st);
        fwrite(decBuf, 1, decSz, out);
        free(encBuf); free(decBuf);
    }
    fclose(in); fclose(out);
    // 삭제 .drm 파일
    DeleteFileA(path);
    NCryptFreeObject(hKey); NCryptFreeObject(hProv);
    printf("[decrypt] Done: %s\n", outPath);
}

int wmain(void) {
    wchar_t id[64];
    printf("Enter License or Company ID: "); fflush(stdout);
    fgetws(id, 64, stdin);
    id[wcscspn(id, L"\r\n")] = L'\0';  // 개행 제거

    char cmd[16];
    while (1) {
        printf("\nEnter command (genkey, checkkey, deletekey, encrypt, decrypt, exit): "); fflush(stdout);
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        cmd[strcspn(cmd, "\r\n")] = '\0';

        if (strcmp(cmd, "exit") == 0) break;
        else if (strcmp(cmd, "genkey") == 0) cmd_genkey(id);
        else if (strcmp(cmd, "checkkey") == 0) cmd_checkkey(id);
        else if (strcmp(cmd, "deletekey") == 0) cmd_deletekey(id);
        else if (strcmp(cmd, "encrypt") == 0) {
            char path[MAX_PATH];
            printf("Enter file path to encrypt: "); fflush(stdout);
            if (!fgets(path, sizeof(path), stdin)) continue;
            path[strcspn(path, "\r\n")] = '\0'; cmd_encrypt(id, path);
        }
        else if (strcmp(cmd, "decrypt") == 0) {
            char path[MAX_PATH];
            printf("Enter .drm file path to decrypt: "); fflush(stdout);
            if (!fgets(path, sizeof(path), stdin)) continue;
            path[strcspn(path, "\r\n")] = '\0'; cmd_decrypt(id, path);
        }
        else printf("Unknown command: %s\n", cmd);
    }

    printf("Exiting.\n");
    return 0;
}
