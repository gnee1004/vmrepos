// encrypt.c: Encrypts user input using RSA and outputs in hexadecimal
// Supports up to 5000 characters (split into 245-byte chunks)
// Requires OpenSSL 3.0 or higher

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <windows.h>

#define KEY_LENGTH 2048
#define MAX_INPUT_LENGTH 5000
#define HEADER_SIGNATURE "RSAENCv1"
#define HEADER_LENGTH 8
#define MAX_CHUNK_SIZE 245

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void get_file_path(char* buffer, size_t buffer_size, const char* filename) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH); // 실행 파일 경로 가져오기
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) {
        *last_slash = '\0'; // 디렉토리 경로만 추출
    }
    snprintf(buffer, buffer_size, "%s\\%s", exe_path, filename);
    printf("DEBUG: Generated path for %s: %s\n", filename, buffer); // 디버깅 로그
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    BIO* pub_bio = NULL, * priv_bio = NULL, * enc_bio = NULL;
    unsigned char* encrypted = NULL;
    size_t encrypted_length;
    char plainText[MAX_INPUT_LENGTH];
    unsigned char chunk[MAX_CHUNK_SIZE];
    size_t chunk_size;
    char pub_path[MAX_PATH], priv_path[MAX_PATH], enc_path[MAX_PATH];

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    printf("Enter the message to encrypt (max %d characters):\n", MAX_INPUT_LENGTH - 1);
    if (fgets(plainText, MAX_INPUT_LENGTH, stdin) == NULL) {
        fprintf(stderr, "Input error\n");
        exit(1);
    }
    size_t len = strlen(plainText);
    if (len > 0 && plainText[len - 1] == '\n') {
        plainText[len - 1] = '\0';
        len--;
    }
    if (len == 0) {
        fprintf(stderr, "No message entered.\n");
        exit(1);
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_LENGTH) <= 0) {
        handleErrors();
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        handleErrors();
    }
    EVP_PKEY_CTX_free(ctx);

    get_file_path(pub_path, MAX_PATH, "public.pem");
    get_file_path(priv_path, MAX_PATH, "private.pem");
    get_file_path(enc_path, MAX_PATH, "encrypted.bin");

    printf("Saving public key to: %s\n", pub_path);
    printf("Saving private key to: %s\n", priv_path);
    printf("Saving encrypted data to: %s\n", enc_path);

    pub_bio = BIO_new_file(pub_path, "w");
    if (!pub_bio) {
        perror("Failed to open public.pem");
        exit(1);
    }
    if (!PEM_write_bio_PUBKEY(pub_bio, pkey)) {
        handleErrors();
    }
    BIO_free(pub_bio);

    priv_bio = BIO_new_file(priv_path, "w");
    if (!priv_bio) {
        perror("Failed to open private.pem");
        exit(1);
    }
    if (!PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        handleErrors();
    }
    BIO_free(priv_bio);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        handleErrors();
    }

    size_t num_chunks = (len + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    printf("Total number of chunks: %zu\n", num_chunks);

    enc_bio = BIO_new_file(enc_path, "wb");
    if (!enc_bio) {
        perror("Failed to open encrypted.bin");
        exit(1);
    }

    BIO_write(enc_bio, HEADER_SIGNATURE, HEADER_LENGTH);
    uint32_t num_chunks_32 = (uint32_t)num_chunks;
    BIO_write(enc_bio, &num_chunks_32, sizeof(uint32_t));

    size_t offset = 0;
    for (size_t i = 0; i < num_chunks; i++) {
        chunk_size = (len - offset) > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : (len - offset);
        memcpy(chunk, plainText + offset, chunk_size);

        if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_length, chunk, chunk_size) <= 0) {
            handleErrors();
        }
        encrypted = (unsigned char*)OPENSSL_malloc(encrypted_length);
        if (!encrypted) {
            handleErrors();
        }
        if (EVP_PKEY_encrypt(ctx, encrypted, &encrypted_length, chunk, chunk_size) <= 0) {
            handleErrors();
        }

        printf("Chunk %zu (length: %zu):\n", i + 1, encrypted_length);
        print_hex(encrypted, encrypted_length);

        BIO_write(enc_bio, encrypted, encrypted_length);
        OPENSSL_free(encrypted);
        encrypted = NULL;
        offset += chunk_size;
    }

    BIO_free(enc_bio);
    printf("Encrypted data with header saved to %s\n", enc_path);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}