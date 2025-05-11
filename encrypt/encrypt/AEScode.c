#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char* plainText, int plainTextLen, unsigned char* key, //이게 암호화
    unsigned char* iv, unsigned char* cipherText) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int cipherTextLen;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
        handleErrors();
    cipherTextLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) handleErrors();
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return cipherTextLen;
}

int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* key, //여기가 복호화
    unsigned char* iv, unsigned char* plainText) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plainTextLen;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
        handleErrors();
    plainTextLen = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) handleErrors();
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return plainTextLen;
}

int main() {
    unsigned char key[] = "0123456789abcdef0123456789abcdef"; // 32바이트 (256비트)
    unsigned char iv[] = "1234567890abcdef"; // 16바이트 (128비트)

    unsigned char* plainText = (unsigned char*)"My Name is gnee";
    int plainTextLen = strlen((char*)plainText);

    unsigned char cipherText[128] = { 0 };
    unsigned char decryptedText[128] = { 0 };

    int cipherTextLen = encrypt(plainText, plainTextLen, key, iv, cipherText);
    printf("Ciphertext is:\n");
    // BIO_dump_fp 대신 직접 출력
    for (int i = 0; i < cipherTextLen; i++) {
        printf("%02x ", cipherText[i]);
    }
    printf("\n");

    int decryptedTextLen = decrypt(cipherText, cipherTextLen, key, iv, decryptedText);
    decryptedText[decryptedTextLen] = '\0';
    printf("Decrypted text is: %s\n", decryptedText);

    system("pause");
    return 0;
}
