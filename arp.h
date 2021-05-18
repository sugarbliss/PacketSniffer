#ifndef ARP_H
#define ARP_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

// ARP Header

struct sniff_arp {
    uint16_t ah_hardware; // 硬件类型
    uint16_t ah_protocol; // 协议类型
    uint8_t ah_hlen; // 硬件地址长度
    uint8_t ah_plen; // 协议地址长度
    uint16_t ah_opcode; // ARP操作码
};

#define ARP_HARDWARE_TYPE_ETHERNET 1
#define ARP_PROTOCOL_TYPE_IPV4 0x0800

#define ARP_MAC_LENGTH 6
#define ARP_IPv4_LENGTH 4

#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_REPLY 2

void handle_arp(QList<QStandardItem*>* row, const struct sniff_arp* arp);
void handle_arp_fill(QString* infoStr, const struct sniff_arp* arp);

#endif // ARP_H
