#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr); 
    abort();
}

int encrypt(unsigned char* plainText, int plainTextLen, unsigned char* key,
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

int main() {
    unsigned char key[] = "0123456789abcdef0123456789abcdef"; 
    unsigned char iv[] = "1234567890abcdef"; 

    unsigned char* plainText = (unsigned char*)"Hello, OpenSSL!";
    int plainTextLen = strlen((char*)plainText); 

    unsigned char cipherText[128] = { 0 };

    int cipherTextLen = encrypt(plainText, plainTextLen, key, iv, cipherText);

    printf("Ciphertext is:\n");
    for (int i = 0; i < cipherTextLen; i++) {
        printf("%02x ", cipherText[i]); 
    }
    printf("\n");

    FILE* fp = fopen("ciphertext.bin", "wb"); 
    if (fp) {
        fwrite(&cipherTextLen, sizeof(int), 1, fp);
        fwrite(cipherText, 1, cipherTextLen, fp);
        fclose(fp); 
        printf("Ciphertext saved to ciphertext.bin\n");
    }
    else {
        printf("Failed to open file for writing\n");
        return 1;
    }

    system("pause"); 
    return 0;
}