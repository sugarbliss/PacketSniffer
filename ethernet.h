#ifndef ETHERNET_H
#define ETHERNET_H

#include <pcap.h>
#include <stdint.h>

#include <QPlainTextEdit>
#include <QStandardItemModel>
#include <vector>

// 以太网头和宏
#define SIZE_ETHERNET 14
struct sniff_ethernet {
    uint8_t ether_dhost[6]; // 以太网源地址, ex: 00:00:00:00:00:00
    uint8_t ether_shost[6]; // 以太网目的地址, ex: 00:00:00:00:00:00
    uint16_t ether_type; // 以太网类型. IP? ARP? RARP? etc
};
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

void handle_ethernet(
    QList<QStandardItem*>* row,
    const uint8_t* packet); // 处理传入的数据包，填写表格行的列
void handle_ethernet_fill(QString* infoStr,
    const char* data); // 用数据包的完整摘要填写textEdit

#endif // ETHERNET_H