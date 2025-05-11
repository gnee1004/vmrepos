#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <windows.h>
#include <errno.h>
#include <ctype.h>

#define KEY_LENGTH 2048
#define HEADER_SIGNATURE "RSAENCv1"
#define HEADER_LENGTH 8

// 허용된 파일 확장자 목록
const char* ALLOWED_EXTENSIONS[] = { "pdf", "hwp", "hwpx", "xlel", "docx", "pptx", "xlsx" };
const int NUM_EXTENSIONS = 7;

// 허용된 경로
const char* ALLOWED_PATH = "C:\\Users\\geunh\\Documents\\RSAFiles";

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// 문자열을 소문자로 변환
void to_lowercase(char* str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

// 파일 확장자 확인
int is_allowed_extension(const char* filename) {
    char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) return 0;

    char ext[10];
    strncpy(ext, dot + 1, sizeof(ext) - 1);
    ext[sizeof(ext) - 1] = '\0';
    to_lowercase(ext);

    for (int i = 0; i < NUM_EXTENSIONS; i++) {
        if (strcmp(ext, ALLOWED_EXTENSIONS[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 경로가 허용된 경로인지 확인
int is_allowed_path(const char* path) {
    char normalized_path[MAX_PATH];
    strncpy(normalized_path, path, MAX_PATH - 1);
    normalized_path[MAX_PATH - 1] = '\0';
    to_lowercase(normalized_path);

    char allowed_path[MAX_PATH];
    strncpy(allowed_path, ALLOWED_PATH, MAX_PATH - 1);
    allowed_path[MAX_PATH - 1] = '\0';
    to_lowercase(allowed_path);

    return (strncmp(normalized_path, allowed_path, strlen(allowed_path)) == 0);
}

// 경로와 파일명을 결합
void construct_file_path(char* buffer, size_t buffer_size, const char* directory, const char* filename) {
    snprintf(buffer, buffer_size, "%s\\%s", directory, filename);
    printf("DEBUG: Generated path for %s: %s\n", filename, buffer);
    if (_access(buffer, 0) != 0) {
        printf("DEBUG: File %s does not exist or cannot be accessed! Error: %s\n", buffer, strerror(errno));
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    char directory[MAX_PATH];
    printf("Enter the directory where files are located (e.g., C:\\Path\\To\\Directory):\n");
    fgets(directory, MAX_PATH, stdin);
    directory[strcspn(directory, "\n")] = '\0';

    // 경로 확인
    if (!is_allowed_path(directory)) {
        printf("ERROR: Directory '%s' is not allowed. Only '%s' is permitted.\n", directory, ALLOWED_PATH);
        return 1;
    }

    // 복호화 대상 파일은 encrypted.bin으로 고정
    char enc_path[MAX_PATH];
    construct_file_path(enc_path, MAX_PATH, directory, "encrypted.bin");

    // 원본 파일 확장자 확인
    char original_filename[MAX_PATH];
    printf("Enter the original file name with extension (e.g., document.pdf):\n");
    scanf("%s", original_filename);
    if (!is_allowed_extension(original_filename)) {
        printf("ERROR: Unsupported file extension in '%s'. Allowed extensions: pdf, hwp, hwpx, xlel, docx, pptx, xlsx\n", original_filename);
        return 1;
    }

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    BIO* priv_bio = NULL, * enc_bio = NULL;
    unsigned char encrypted[KEY_LENGTH / 8] = { 0 };
    unsigned char* decrypted = NULL;
    char header[HEADER_LENGTH + 1] = { 0 };
    size_t encrypted_length, decrypted_length;
    char* final_message = NULL;
    size_t final_length = 0;
    char priv_path[MAX_PATH];

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    construct_file_path(priv_path, MAX_PATH, directory, "private.pem");

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