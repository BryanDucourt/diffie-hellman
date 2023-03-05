//
// Created by bryandu on 22-6-19.
//
#include <iostream>
#include "AES.h"
#include "DH.h"
#include <cstdlib>
#include <cstring>
#include "unistd.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

int main(int argc, char *argv[]) {
    uchar pk[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uchar msg[8] = "pre_msg";
    time_t t;
    srand(time(nullptr));
    DiffieHellman client{}, server{};
    tuple<unsigned int, unsigned int> r = client.GenerateExKey();

    char addr[] = "127.0.0.1";
    char *default_addr = reinterpret_cast<char *>(&addr);
    int port = 8080;
    bool psk = false;
    int max_buffer = 40;
    switch (argc) {
        case 4:
            psk = atoi(argv[3]);
        case 3:
            port = atoi(argv[2]);
        case 2:
            default_addr = argv[1];
        case 1:
            break;
        default:
            cout << "- usage: ./DH_CLIENT [ADDRESS(OPTIONAL)] [PORT(OPTIONAL)] [USE PSK(OPTIONAL)]" << endl;
            exit(0);
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int flag = 0;
    std::cout << "- connecting to server_compose" << std::endl;
    struct sockaddr_in serv_addr{};
    memset(&serv_addr, 0, sizeof serv_addr);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(default_addr);
    serv_addr.sin_port = htons(port);
    int max_try = 3;
    while (max_try > 0) {
        int res = connect(sock, (struct sockaddr *) &serv_addr, sizeof serv_addr);
        if (res == 0) {
            std::cout << "- connect succeed" << std::endl;
            break;
        } else {
            std::cout << "- connect to server_compose failed, retrying" << std::endl;
        }
        max_try--;
    }
    if (max_try == 0) {
        std::cout << "- max retry exceeded, please check your network." << std::endl;
        std::cout << "- exiting..." << std::endl;
        exit(0);
    }
    uchar buffer[40] = {0};
    uchar buffer_recv[40] = {0};
    AES *enc;
    if (psk) {
        enc = new AES(pk);
        uchar dh_buffer[20];
        memset(dh_buffer,0xff,20);
        memcpy(dh_buffer+1,msg,8);
        send(sock,dh_buffer,20,0);
        recv(sock,dh_buffer,20,0);
        uchar re_msg[16];
        memcpy(re_msg,dh_buffer+1,16);
        enc->Decrypt(re_msg,16);
        uchar dec[8];
        memcpy(dec,re_msg,8);
        if (memcmp(msg,dec,8)!=0){
            cout<<"PSK校验失败！"<<endl;
            close(sock);
            return 0;
        }
    } else {
        uchar dh_buffer[20];
        memset(dh_buffer, 0xff, 20);
        unsigned int trans_key = get<0>(r);
        unsigned int mod_p = get<1>(r);
        memcpy(dh_buffer + 1, &trans_key, sizeof(unsigned int));
        memcpy(dh_buffer + 1 + sizeof(unsigned int), &mod_p, sizeof(unsigned int));
        cout << "模数：" << hex << mod_p << endl;
        cout << "公钥：" << hex << trans_key << endl;
        send(sock, dh_buffer, 20, 0);
        recv(sock, dh_buffer, 20, 0);
        unsigned int recv_key = 0;
        memcpy(&recv_key, dh_buffer + 1, sizeof(unsigned int));
        cout<<"服务端公钥："<<hex<<recv_key<<endl;
        client.UpdateRecvKey(recv_key);
        client.GeneratePubKey();
        cout << "密钥：" << hex << client.public_key << endl;

        uchar aes_key[16];
        for (int i = 0; i < 4; i++) {
            memcpy(aes_key + i * sizeof(unsigned int), &(client.public_key), sizeof(unsigned int));
        }
        enc = new AES(aes_key);
    }
    while (true) {
        memset(buffer, 0, max_buffer);
        memset(buffer_recv, 0, max_buffer);
        cout << "< ";
        cin >> buffer;
        size_t length = strlen(reinterpret_cast<const char *>(buffer));
        uchar s_buffer[length];
        memcpy(s_buffer, buffer, length);
        s_buffer[length] = '\0';
        pair<uchar *, int> encrypted = enc->Encrypt(s_buffer, length);
        uchar s[encrypted.second + 1];
        s[0] = 0xfb;
        memcpy(s + 1, encrypted.first, encrypted.second);
        send(sock, s, encrypted.second + 1, 0);
        if (strcmp("exit", reinterpret_cast<const char *>(buffer)) == 0) {
            break;
        }
//        int len = recv(sock,buffer_recv, max_buffer,0);
//        buffer_recv[len]='\0';
//        cout<<"> "<<buffer_recv<<endl;
    }
    close(sock);
}