//
// Created by bryandu on 22-6-20.
//

#ifndef DIFFIE_HELLMAN_AES_H
#define DIFFIE_HELLMAN_AES_H
#endif //DIFFIE_HELLMAN_AES_H
#pragma once

#define uchar unsigned char
#include "utility"
//#define ushort unsigned short

class AES{
public:
    AES(unsigned char key[16]);
    ~AES();
    std::pair<uchar *,int> Encrypt(unsigned char plain_text[], int length);
    uchar* Decrypt(uchar cipher_text[],int length);
private:
    uchar encrypt_permutation_table[16][16]{};
    uchar decrypt_permutation_table[16][16]{};
    unsigned int round_key[44];
    void KeyExpansion(const uchar key[16]);
    unsigned int SubByte(unsigned int word);
    void SubByte(unsigned char * plain_text,int length);
    void InvSubByte(unsigned char * plain_text,int length);
    static unsigned int RotByte(unsigned int word);
    void AddRoundKey(int round, unsigned char *plain_text, int length);
    static void ShiftRow(unsigned char *plain_text,int length);
    static void InvShiftRow(unsigned char *plain_text,int length);
    static void MixCol(unsigned char *plain_text,int length);
    static void InvMixCol(unsigned char *plain_text,int length);
    static unsigned char GaloisMultiplication(unsigned char Num_L, unsigned char Num_R);

};