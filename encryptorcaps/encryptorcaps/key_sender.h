// key_sender.h - Ű ���ۿ� ���

#ifndef KEY_SENDER_H
#define KEY_SENDER_H

int send_key_to_server(const char* hostname, const unsigned char* key, const unsigned char* iv);

#endif // KEY_SENDER_H
// key_sender.c - ��ȣȭ�� AES Ű/IV�� ������ ������ ����
