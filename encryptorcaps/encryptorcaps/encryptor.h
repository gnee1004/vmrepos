#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <windows.h>

#define AES_KEY_SIZE 32     // AES-256 ���
#define AES_BLOCK_SIZE 16

// ��ȣȭ �Լ�
void encrypt_file(const char* filepath, const unsigned char* key, const unsigned char* iv);

// Ű/IV ���� �Լ� (����ȭ�� �� XOR ������)
void restore_key(unsigned char* key_out);
void restore_iv(unsigned char* iv_out);


#endif // ENCRYPTOR_H
