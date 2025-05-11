#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

size_t encrypt(unsigned char* plainText, size_t plainTextLen, unsigned char* key,
    unsigned char* iv, unsigned char* cipherText) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int cipherTextLen;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, (int)plainTextLen))
        handleErrors();
    cipherTextLen = len;
    if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) handleErrors();
    cipherTextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    return (size_t)cipherTextLen;
}

size_t getFileSize(FILE* file) {
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int main() {
    unsigned char key[] = "0123456789abcdef0123456789abcdef";
    unsigned char iv[] = "1234567890abcdef";
    char inputText[5001];
    unsigned char* plainText = NULL;
    size_t plainTextLen = 0;
    unsigned char cipherText[6000] = { 0 };
    const char headerSignature[] = "AESENC";

    printf("AESencryptProject - File Encryption\n");

    // ciphertext.bin 저장 경로 입력
    char outputFilePath[256] = "ciphertext.bin"; // 기본 경로
    printf("Enter the path to save the encrypted file (press Enter for default 'ciphertext.bin'): ");
    fgets(outputFilePath, sizeof(outputFilePath), stdin);
    outputFilePath[strcspn(outputFilePath, "\n")] = '\0';
    if (strlen(outputFilePath) == 0) {
        strcpy(outputFilePath, "ciphertext.bin"); // 기본 경로 사용
    }

    printf("Select input method:\n");
    printf("1. Enter text manually\n");
    printf("2. Read from file\n");
    printf("Enter choice (1 or 2): ");
    char choice[10];
    fgets(choice, sizeof(choice), stdin);
    choice[strcspn(choice, "\n")] = '\0';

    if (strcmp(choice, "1") == 0) {
        printf("Enter the text to encrypt (max 5000 characters):\n");
        if (fgets(inputText, sizeof(inputText), stdin) == NULL) {
            printf("Failed to read input\n");
            return 1;
        }

        size_t inputLen = strlen(inputText);
        if (inputLen > 0 && inputText[inputLen - 1] == '\n') {
            inputText[inputLen - 1] = '\0';
            inputLen--;
        }

        if (inputLen == 0) {
            printf("No input provided\n");
            return 1;
        }

        if (inputLen > 5000) {
            printf("Input exceeds 5000 characters\n");
            return 1;
        }

        plainText = (unsigned char*)inputText;
        plainTextLen = inputLen;
    }
    else if (strcmp(choice, "2") == 0) {
        char filePath[256];
        printf("Enter the path of the file to encrypt: ");
        fgets(filePath, sizeof(filePath), stdin);
        filePath[strcspn(filePath, "\n")] = '\0';

        FILE* inputFile = fopen(filePath, "rb");
        if (!inputFile) {
            printf("Failed to open input file: %s\n", filePath);
            return 1;
        }

        plainTextLen = getFileSize(inputFile);
        if (plainTextLen > 5000) {
            printf("File size exceeds 5000 bytes\n");
            fclose(inputFile);
            return 1;
        }

        plainText = (unsigned char*)malloc(plainTextLen + 1);
        if (!plainText) {
            printf("Memory allocation failed\n");
            fclose(inputFile);
            return 1;
        }

        fread(plainText, 1, plainTextLen, inputFile);
        plainText[plainTextLen] = '\0';
        fclose(inputFile);
    }
    else {
        printf("Invalid choice\n");
        return 1;
    }

    size_t cipherTextLen = encrypt(plainText, plainTextLen, key, iv, cipherText);

    printf("Ciphertext is:\n");
    for (size_t i = 0; i < cipherTextLen; i++) {
        printf("%02x ", cipherText[i]);
    }
    printf("\n");

    FILE* fp = fopen(outputFilePath, "wb");
    if (fp) {
        fwrite(headerSignature, 1, 6, fp);
        fwrite(&cipherTextLen, sizeof(size_t), 1, fp);
        fwrite(cipherText, 1, cipherTextLen, fp);
        fclose(fp);
        printf("Ciphertext saved to %s\n", outputFilePath);
    }
    else {
        printf("Failed to open file for writing: %s\n", outputFilePath);
        if (plainText != (unsigned char*)inputText) free(plainText);
        return 1;
    }

    if (plainText != (unsigned char*)inputText) free(plainText);
    system("pause");
    return 0;
}