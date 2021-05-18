#ifndef IPV4_H
#define IPV4_H

#include <netinet/in.h>
#include <stdint.h>

#include <QList>
#include <QStandardItem>

//IPv4 header and macros
struct sniff_ipv4 {
    uint8_t ip_vhl; // 版本和首部长度
    uint8_t ip_tos; // 服务质量
    uint16_t ip_len; // 有效载荷长度
    uint16_t ip_id; // 标识
    uint16_t ip_off; // 偏移
    uint8_t ip_ttl; // 生存时间
    uint8_t ip_p; // 协议类型
    uint16_t ip_sum; // 校验和
    struct in_addr ip_src; // 源地址
    struct in_addr ip_dst; // 目的地址
};

//ip_vhl字段的宏
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f) // 计算头部长度
#define IP_V(ip) (((ip)->ip_vhl) >> 4) // 计算IP版本

#define IP_RF 0x8000 // 保留片段标志位
#define IP_DF 0x4000 // 分片标志位（1：不分片  0：分片）
#define IP_MF 0x2000 // 更多分片  （1：后面还有分片  0：最后一个分片）

#define IP_OFFMASK 0x1fff // 位掩码标志位

// ip_off字段的宏
#define IP_OFFSET(ip) ((ntohs((ip)->ip_off)) & IP_OFFMASK) // 计算片段偏移

void handle_ipv4(QList<QStandardItem*>* row, const struct sniff_ipv4* ip);
void handle_ipv4_fill(QString* infoStr, const struct sniff_ipv4* ip);

#endif // IPV4_H
