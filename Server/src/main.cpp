//
// Created by bryandu on 22-6-19.
//
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "cstring"
#include "DH.h"
#include "AES.h"
using namespace std;

int main(int argc, char *argv[]) {
    cout << "- creating TCP server_compose..." << endl;
    DiffieHellman server{};
    uchar pk[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    char default_addr[] = "127.0.0.1";
    char *listen_addr = default_addr;
    int flag = 0;
    int port = 8080;
    int max_buffer = 1024;
    bool psk = false;
    switch (argc) {
        case 4:
            psk = atoi(argv[3]);
        case 3:
            port = atoi(argv[2]);
        case 2:
            listen_addr = argv[1];
        case 1:
            break;
        default:
            cout << "- usage: ./DH_SERVER [ADDRESS(OPTIONAL)] [PORT(OPTIONAL)] [USE PSK(OPTIONAL 0/1)]" << endl;
            cout << "- exiting..." << endl;
            exit(0);
    }
    int serv_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr{};
    memset(&serv_addr, 0, sizeof serv_addr);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(listen_addr);
    serv_addr.sin_port = htons(port);
    int res = bind(serv_socket, (struct sockaddr *) &serv_addr, sizeof serv_addr);
    if (res == 0) {
        cout << "- server_compose created!" << endl;
    } else {
        cout << "- server_compose create failed, exiting" << endl;
        exit(0);
    }
    listen(serv_socket, 20);

    struct sockaddr_in client_addr{};
    socklen_t size = sizeof client_addr;
    char buffer[40] = {0};
    int client_socket = accept(serv_socket, (struct sockaddr *) &client_addr, &size);
    cout << "connection from " <<inet_ntoa(client_addr.sin_addr)<< endl;
    AES *enc;
    while (true) {

        if (flag == 0) {
            if (psk){
                enc = new AES(pk);
                uchar dh_buffer[20];
                recv(client_socket,dh_buffer,20,0);
                uchar verify[8];
                memcpy(verify,dh_buffer+1,8);
                pair<uchar *, int> encrypted = enc->Encrypt(verify,8);
                memcpy(dh_buffer+1,encrypted.first,encrypted.second);
                send(client_socket,dh_buffer,20,0);
                flag=1;

            } else {
                int len = recv(client_socket, buffer, max_buffer, 0);
                unsigned int recv_key = 0, p = 0;
                memcpy(&recv_key, buffer + 1, sizeof(unsigned int));
                memcpy(&p, buffer + 1 + sizeof(unsigned int), sizeof(unsigned int));
                cout<<"客户端公钥："<<hex<<recv_key<<endl;
                cout<<"模数："<<hex<<p<<endl;
                unsigned int key = server.GenerateExKey(2, p);
                server.UpdateRecvKey(recv_key);
                memset(buffer, 0xfe, 40);
                memcpy(buffer + 1, &key, sizeof key);
                send(client_socket, buffer, max_buffer, 0);
                flag = 1;
                server.GeneratePubKey();
                cout<<"公钥："<<hex<<key<<endl;
                cout << "密钥：" << hex << server.public_key << endl;
                memset(buffer, 0, max_buffer);
                uchar aes_key[16];
                for (int i = 0; i < 4; i++) {
                    memcpy(aes_key + i * sizeof(unsigned int), &(server.public_key), sizeof(unsigned int));
                }
                enc = new AES(aes_key);
            }
        } else {
            int len = recv(client_socket, buffer, max_buffer, 0);
            uchar plain[len-1];
            memset(plain,0,len-1);
            memcpy(plain,buffer+1,len-1);
            enc->Decrypt(plain,len-1);
            int length = plain[len-3];
            uchar text[length+1];
            memcpy(text,plain,length);
            text[length] = '\0';
            cout << text << endl;
            if (strcmp("exit", reinterpret_cast<const char *>(text)) == 0) {
                break;
            }


        }
    }
    close(client_socket);
    close(serv_socket);
}