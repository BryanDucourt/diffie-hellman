//
// Created by bryandu on 22-6-26.
//

#ifndef DIFFIE_HELLMAN_DH_H
#define DIFFIE_HELLMAN_DH_H

#endif //DIFFIE_HELLMAN_DH_H
#pragma once
#include "cmath"
#include <ctime>
#include <cstdlib>
#include "tuple"
using namespace std;

unsigned int GenerateRandomOdd();
size_t RepeatMod(size_t base, size_t n, size_t mod);
bool RobinMiller(size_t n,size_t k);

class DiffieHellman{
public:
    unsigned int public_key;
    unsigned int exchange_key;
    unsigned int generator;
    unsigned int mod_p;
    tuple<unsigned int,unsigned int> GenerateExKey();
    unsigned int GenerateExKey(unsigned int generator,unsigned int mod);
    void GeneratePubKey();
    void UpdateRecvKey(unsigned int key);
private:
    unsigned int private_key;
    unsigned int recv_key;

};