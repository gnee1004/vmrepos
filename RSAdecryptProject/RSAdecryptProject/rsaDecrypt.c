#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h> // Windows에서 access 함수를 위해 추가
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <windows.h>
#include <errno.h> // errno 및 strerror 사용을 위해 추가

#define KEY_LENGTH 2048
#define HEADER_SIGNATURE "RSAENCv1"
#define HEADER_LENGTH 8

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void get_file_path(char* buffer, size_t buffer_size, const char* filename) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) {
        *last_slash = '\0';
    }
    snprintf(buffer, buffer_size, "%s\\%s", exe_path, filename);
    printf("DEBUG: Generated path for %s: %s\n", filename, buffer);
    // Windows에서 _access 사용, F_OK 대신 0 사용
    if (_access(buffer, 0) != 0) {
        printf("DEBUG: File %s does not exist or cannot be accessed! Error: %s\n", buffer, strerror(errno));
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    BIO* priv_bio = NULL, * enc_bio = NULL;
    unsigned char encrypted[KEY_LENGTH / 8] = { 0 };
    unsigned char* decrypted = NULL;
    char header[HEADER_LENGTH + 1] = { 0 };
    size_t encrypted_length, decrypted_length;
    char* final_message = NULL;
    size_t final_length = 0;
    char priv_path[MAX_PATH], enc_path[MAX_PATH];

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    get_file_path(priv_path, MAX_PATH, "private.pem");
    get_file_path(enc_path, MAX_PATH, "encrypted.bin");

    printf("Attempting to read private key from: %s\n", priv_path);
    priv_bio = BIO_new_file(priv_path, "r");
    if (!priv_bio) {
        printf("ERROR: Failed to open private.pem. Error: %s\n", strerror(errno));
        exit(1);
    }
    printf("DEBUG: Successfully opened private.pem\n");

    pkey = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
    if (!pkey) {
        printf("ERROR: Failed to read private key from private.pem\n");
        ERR_print_errors_fp(stderr);
        BIO_free(priv_bio);
        exit(1);
    }
    printf("DEBUG: Successfully read private key\n");
    BIO_free(priv_bio);

    printf("Attempting to read encrypted data from: %s\n", enc_path);
    enc_bio = BIO_new_file(enc_path, "rb");
    if (!enc_bio) {
        printf("ERROR: Failed to open encrypted.bin. Error: %s\n", strerror(errno));
        exit(1);
    }
    printf("DEBUG: Successfully opened encrypted.bin\n");

    if (BIO_read(enc_bio, header, HEADER_LENGTH) != HEADER_LENGTH) {
        fprintf(stderr, "Failed to read header signature\n");
        BIO_free(enc_bio);
        exit(1);
    }
    if (strncmp(header, HEADER_SIGNATURE, HEADER_LENGTH) != 0) {
        fprintf(stderr, "Invalid header signature\n");
        BIO_free(enc_bio);
        exit(1);
    }

    uint32_t num_chunks;
    if (BIO_read(enc_bio, &num_chunks, sizeof(uint32_t)) != sizeof(uint32_t)) {
        fprintf(stderr, "Failed to read number of chunks\n");
        BIO_free(enc_bio);
        exit(1);
    }
    printf("Total number of chunks: %u\n", num_chunks);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        handleErrors();
    }

    for (uint32_t i = 0; i < num_chunks; i++) {
        encrypted_length = BIO_read(enc_bio, encrypted, KEY_LENGTH / 8);
        if (encrypted_length != KEY_LENGTH / 8) {
            fprintf(stderr, "Failed to read encrypted chunk %u\n", i + 1);
            BIO_free(enc_bio);
            exit(1);
        }

        if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_length, encrypted, encrypted_length) <= 0) {
            handleErrors();
        }
        decrypted = (unsigned char*)OPENSSL_malloc(decrypted_length);
        if (!decrypted) {
            handleErrors();
        }
        if (EVP_PKEY_decrypt(ctx, decrypted, &decrypted_length, encrypted, encrypted_length) <= 0) {
            handleErrors();
        }

        final_message = (char*)realloc(final_message, final_length + decrypted_length + 1);
        memcpy(final_message + final_length, decrypted, decrypted_length);
        final_length += decrypted_length;
        final_message[final_length] = '\0';

        OPENSSL_free(decrypted);
        decrypted = NULL;
    }

    BIO_free(enc_bio);

    printf("Decrypted message: %s\n", final_message);

    free(final_message);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}