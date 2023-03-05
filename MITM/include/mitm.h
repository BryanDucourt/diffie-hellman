//
// Created by bryandu on 22-6-28.
//

#ifndef DIFFIE_HELLMAN_MITM_H
#define DIFFIE_HELLMAN_MITM_H

#endif //DIFFIE_HELLMAN_MITM_H
#pragma once
#include <pcap.h>
typedef struct IP_T
{
    unsigned char client_ip[16];
    unsigned char server_ip[16];
    pcap_t *p;
} IP_T;

typedef struct psd_header
{
    unsigned int saddr;
    unsigned int daddr;
    char must_be_zero;      // 保留字，强制置空
    char protocol;          // 协议类型
    unsigned short tcp_len; // TCP长度
} psd_header;

void process_pkt(IP_T *ip_t, const struct pcap_pkthdr *pkthdr, const u_char *packet);
uint16_t calc_checksum(void *pkt, int len);
void set_psd_header(struct psd_header *ph, struct iphdr *ip, uint16_t tcp_len);