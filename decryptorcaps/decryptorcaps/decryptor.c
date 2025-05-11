#include "decryptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <openssl/evp.h>

#define FILENAME_MAXLEN 256

// XOR 마스크
static const unsigned char xor_mask = 0xA5;

// 난독화된 AES-256 키 (32바이트)
static const unsigned char obfuscated_key[32] = {
    0x14, 0x5d, 0x52, 0x3b, 0xd8, 0xa7, 0xa4, 0xeb,
    0x9d, 0x00, 0x6c, 0x42, 0x26, 0x8d, 0xd3, 0x18,
    0x5f, 0x12, 0x22, 0xad, 0xb8, 0xc2, 0x1a, 0x5f,
    0xac, 0x71, 0x96, 0x9e, 0xce, 0xc7, 0x6b, 0xd9
};

// 난독화된 IV (16바이트)
static const unsigned char obfuscated_iv[16] = {
    0x99, 0xdb, 0xbc, 0xef, 0xa5, 0x77, 0xf0, 0x16,
    0x33, 0x84, 0x5b, 0xcb, 0x01, 0xac, 0x75, 0x69
};

// 복호화 키 복원
void restore_key(unsigned char* key_out) {
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        key_out[i] = obfuscated_key[i] ^ xor_mask;
    }
}

// IV 복원
void restore_iv(unsigned char* iv_out) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv_out[i] = obfuscated_iv[i] ^ xor_mask;
    }
}

// 복호화 실행
int decrypt_file(const char* encrypted_path, const unsigned char* key, const unsigned char* iv) {
    FILE* in = fopen(encrypted_path, "rb");
    if (!in) {
        printf("[!] 파일 열기 실패: %s\n", encrypted_path);
        return 0;
    }

    fseek(in, 0, SEEK_END);
    long filesize = ftell(in);
    rewind(in);

    if (filesize <= FILENAME_MAXLEN) {
        fclose(in);
        printf("[!] 파일 크기 비정상 (너무 작음): %s\n", encrypted_path);
        return 0;
    }

    unsigned char* encrypted_data = malloc(filesize);
    if (!encrypted_data) {
        fclose(in);
        printf("[!] 메모리 할당 실패 (encrypted_data)\n");
        return 0;
    }

    fread(encrypted_data, 1, filesize, in);
    fclose(in);

    unsigned char* decrypted_data = malloc(filesize);
    if (!decrypted_data) {
        free(encrypted_data);
        printf("[!] 메모리 할당 실패 (decrypted_data)\n");
        return 0;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_data);
        free(decrypted_data);
        printf("[!] EVP context 생성 실패\n");
        return 0;
    }

    int len = 0, decrypted_len = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto cleanup;
    if (!EVP_DecryptUpdate(ctx, decrypted_data, &len, encrypted_data, (int)filesize)) goto cleanup;
    decrypted_len = len;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_data + len, &len)) goto cleanup;
    decrypted_len += len;

    if (decrypted_len <= FILENAME_MAXLEN) {
        printf("[!] 복호화 결과 비정상: %s\n", encrypted_path);
        goto cleanup;
    }

    char original_name[FILENAME_MAXLEN] = { 0 };
    memcpy(original_name, decrypted_data + decrypted_len - FILENAME_MAXLEN, FILENAME_MAXLEN - 1);
    decrypted_len -= FILENAME_MAXLEN;

    char output_path[MAX_PATH];
    snprintf(output_path, MAX_PATH, "%s", original_name);

    FILE* out = fopen(output_path, "wb");
    if (!out) {
        printf("[!] 복호화 파일 저장 실패: %s\n", output_path);
        goto cleanup;
    }

    fwrite(decrypted_data, 1, decrypted_len, out);
    fclose(out);

    // 복호화 성공 시 .adr 파일 삭제
    DeleteFileA(encrypted_path);

    printf("[+] 복호화 완료: %s\n", output_path);

    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    free(decrypted_data);
    return 1;

cleanup:
    printf("[!] 복호화 실패: %s\n", encrypted_path);
    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    free(decrypted_data);
    return 0;
}
