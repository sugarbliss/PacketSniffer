#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//IPv6 header and macros
struct sniff_ipv6 {
    uint32_t ip6_vtcfl; // 版本，流量类型，流标签
    uint16_t ip6_len; // 有效载荷的长度
    uint8_t ip6_p; // 协议类型
    uint8_t ip6_hop; // 跳数限制
    char ip6_src[16]; // 源地址
    char ip6_dst[16]; // 目的地址
};
#define IPV6_HEADER_LENGTH 40
#define IPV6_VERSION(ip6) ((ip6)->ip6_vtcfl & 0xF0000000)

void handle_ipv6(QList<QStandardItem*>* row, const struct sniff_ipv6* ip6);

#endif // IPV6_H