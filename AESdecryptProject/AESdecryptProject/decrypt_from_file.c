#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

size_t decrypt(unsigned char* cipherText, size_t cipherTextLen, unsigned char* key,
    unsigned char* iv, unsigned char* plainText) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plainTextLen;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, (int)cipherTextLen))
        handleErrors();
    plainTextLen = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) handleErrors();
    plainTextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    return (size_t)plainTextLen;
}

int main() {
    unsigned char key[] = "0123456789abcdef0123456789abcdef";
    unsigned char iv[] = "1234567890abcdef";
    unsigned char cipherText[6000] = { 0 };
    unsigned char decryptedText[5100] = { 0 };
    size_t cipherTextLen;
    const char expectedHeader[] = "AESENC";
    char readHeader[7] = { 0 };

    printf("AESdecryptProject - File Decryption\n");

    // ciphertext.bin 읽기 경로 입력
    char inputFilePath[256] = "ciphertext.bin"; // 기본 경로
    printf("Enter the path of the encrypted file to decrypt (press Enter for default 'ciphertext.bin'): ");
    fgets(inputFilePath, sizeof(inputFilePath), stdin);
    inputFilePath[strcspn(inputFilePath, "\n")] = '\0';
    if (strlen(inputFilePath) == 0) {
        strcpy(inputFilePath, "ciphertext.bin"); // 기본 경로 사용
    }

    FILE* fp = fopen(inputFilePath, "rb");
    if (fp) {
        fread(readHeader, 1, 6, fp);
        readHeader[6] = '\0';
        if (strcmp(readHeader, expectedHeader) != 0) {
            printf("Invalid file format: incorrect header signature\n");
            fclose(fp);
            return 1;
        }

        fread(&cipherTextLen, sizeof(size_t), 1, fp);
        if (cipherTextLen > sizeof(cipherText)) {
            printf("Ciphertext too large for buffer\n");
            fclose(fp);
            return 1;
        }

        fread(cipherText, 1, cipherTextLen, fp);
        fclose(fp);
        printf("Read %zu bytes from %s\n", cipherTextLen, inputFilePath);
    }
    else {
        printf("Failed to open file: %s\n", inputFilePath);
        return 1;
    }

    size_t decryptedTextLen = decrypt(cipherText, cipherTextLen, key, iv, decryptedText);

    char outputFilePath[256];
    printf("Enter the path to save the decrypted file: ");
    fgets(outputFilePath, sizeof(outputFilePath), stdin);
    outputFilePath[strcspn(outputFilePath, "\n")] = '\0';

    FILE* outputFile = fopen(outputFilePath, "wb");
    if (outputFile) {
        fwrite(decryptedText, 1, decryptedTextLen, outputFile);
        fclose(outputFile);
        printf("Decrypted data saved to %s\n", outputFilePath);
    }
    else {
        printf("Failed to open output file: %s\n", outputFilePath);
        return 1;
    }

    decryptedText[decryptedTextLen] = '\0';
    printf("Decrypted text is: %s\n", decryptedText);

    system("pause");
    return 0;
}