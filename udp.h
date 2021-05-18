#ifndef UDP_H
#define UDP_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//UDP header
struct sniff_udp {
    uint16_t uh_sport; // 源端口
    uint16_t uh_dport; // 目的端口
    uint16_t uh_len; // 长度
    uint16_t uh_sum; // 校验和
};

void handle_udp(QList<QStandardItem*>* row, const struct sniff_udp* udp);
void handle_udp_fill(QString* infoStr, const struct sniff_udp* udp);

#endif // UDP_H
