#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <windows.h>
#include <ctype.h>

#define KEY_LENGTH 2048
#define MAX_MESSAGE_LENGTH 5000
#define CHUNK_SIZE 245
#define HEADER_SIGNATURE "RSAENCv1"
#define HEADER_LENGTH 8

// 허용된 파일 확장자 목록
const char* ALLOWED_EXTENSIONS[] = { "pdf", "hwp", "hwpx", "xlel", "docx", "pptx", "xlsx" };
const int NUM_EXTENSIONS = 7;

// 허용된 경로 (예: C:\Users\geunh\Documents\RSAFiles)
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
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    char directory[MAX_PATH];
    printf("Enter the directory to save files (e.g., C:\\Path\\To\\Directory):\n");
    fgets(directory, MAX_PATH, stdin);
    directory[strcspn(directory, "\n")] = '\0'; // 개행 문자 제거

    // 경로 확인
    if (!is_allowed_path(directory)) {
        printf("ERROR: Directory '%s' is not allowed. Only '%s' is permitted.\n", directory, ALLOWED_PATH);
        return 1;
    }

    char message[MAX_MESSAGE_LENGTH];
    printf("Enter the message to encrypt (max 4999 characters):\n");
    fgets(message, MAX_MESSAGE_LENGTH, stdin);
    message[strcspn(message, "\n")] = '\0';

    if (strlen(message) == 0) {
        printf("ERROR: Message cannot be empty.\n");
        return 1;
    }

    // 메시지를 임시 파일로 저장 (사용자가 선택한 확장자 사용)
    char temp_filename[MAX_PATH];
    char file_extension[10];
    printf("Enter the file extension (e.g., pdf, docx, pptx, xlsx, hwp, hwpx, xlel):\n");
    scanf("%9s", file_extension);
    to_lowercase(file_extension);

    // 확장자 확인
    snprintf(temp_filename, MAX_PATH, "temp_message.%s", file_extension);
    if (!is_allowed_extension(temp_filename)) {
        printf("ERROR: Unsupported file extension '%s'. Allowed extensions: pdf, hwp, hwpx, xlel, docx, pptx, xlsx\n", file_extension);
        return 1;
    }

    char temp_filepath[MAX_PATH];
    construct_file_path(temp_filepath, MAX_PATH, directory, temp_filename);

    FILE* temp_file = fopen(temp_filepath, "wb");
    if (!temp_file) {
        printf("ERROR: Failed to create temporary file '%s'\n", temp_filepath);
        return 1;
    }
    fwrite(message, 1, strlen(message), temp_file);
    fclose(temp_file);

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    BIO* pub_bio = NULL, * priv_bio = NULL, * enc_bio = NULL;
    unsigned char* encrypted = NULL;
    size_t encrypted_length;
    char pub_path[MAX_PATH], priv_path[MAX_PATH], enc_path[MAX_PATH];

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    construct_file_path(pub_path, MAX_PATH, directory, "public.pem");
    construct_file_path(priv_path, MAX_PATH, directory, "private.pem");
    construct_file_path(enc_path, MAX_PATH, directory, "encrypted.bin");

    pkey = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_LENGTH) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        handleErrors();
    }
    EVP_PKEY_CTX_free(ctx);

    printf("Saving public key to: %s\n", pub_path);
    pub_bio = BIO_new_file(pub_path, "w");
    if (!pub_bio || !PEM_write_bio_PUBKEY(pub_bio, pkey)) {
        handleErrors();
    }
    BIO_free(pub_bio);

    printf("Saving private key to: %s\n", priv_path);
    priv_bio = BIO_new_file(priv_path, "w");
    if (!priv_bio || !PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        handleErrors();
    }
    BIO_free(priv_bio);

    FILE* in_file = fopen(temp_filepath, "rb");
    if (!in_file) {
        printf("ERROR: Failed to open temporary file '%s'\n", temp_filepath);
        return 1;
    }

    printf("Saving encrypted data to: %s\n", enc_path);
    enc_bio = BIO_new_file(enc_path, "wb");
    if (!enc_bio) {
        handleErrors();
    }

    BIO_write(enc_bio, HEADER_SIGNATURE, HEADER_LENGTH);

    unsigned char chunk[CHUNK_SIZE];
    size_t chunk_size;
    uint32_t num_chunks = 0;

    BIO* count_bio = BIO_new(BIO_s_mem());
    while ((chunk_size = fread(chunk, 1, CHUNK_SIZE, in_file)) > 0) {
        num_chunks++;
        BIO_write(count_bio, chunk, chunk_size);
    }
    rewind(in_file);

    BIO_write(enc_bio, &num_chunks, sizeof(uint32_t));

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        handleErrors();
    }

    for (uint32_t i = 0; i < num_chunks; i++) {
        chunk_size = fread(chunk, 1, CHUNK_SIZE, in_file);
        if (chunk_size == 0) {
            handleErrors();
        }

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

        printf("Chunk %u (length: %zu):\n", i + 1, encrypted_length);
        for (size_t j = 0; j < encrypted_length; j++) {
            printf("%02X ", encrypted[j]);
            if ((j + 1) % 16 == 0) printf("\n");
        }
        printf("\n");

        BIO_write(enc_bio, encrypted, encrypted_length);
        OPENSSL_free(encrypted);
        encrypted = NULL;
    }

    BIO_free(enc_bio);
    fclose(in_file);

    printf("Encrypted data with header saved to %s\n", enc_path);

    remove(temp_filepath); // 임시 파일 삭제

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}