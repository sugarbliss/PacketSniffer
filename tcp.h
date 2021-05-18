#ifndef TCP_H
#define TCP_H

#include <QList>
#include <QStandardItem>

//TCP header
struct sniff_tcp {
    uint16_t th_sport; // (16 bits) - 源端口
    uint16_t th_dport; // (16 bits) - 目的端口
    uint32_t th_seq; // (32 bits) - 序列号
    uint32_t th_ack; // (32 bits) - 确认序号

    uint8_t th_offx2; // 偏移
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) // 获得TCP头部长度
    uint8_t th_flags; // 标志位
#define TH_CWR 0x80 // 1000 0000 CWR
#define TH_ECE 0x40 // 0100 0000 ECE flag
#define TH_URG 0x20 // 0010 0000 URGENT flag (is urgent pointer set)
#define TH_ACK 0x10 // 0001 0000 ACK flag
#define TH_PSH 0x08 // 0000 1000 PUSH flag
#define TH_RST 0x04 // 0000 0100 RESET flag
#define TH_SYN 0x02 // 0000 0010 SYN flag
#define TH_FIN 0x01 // 0000 0001 FIN flag
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    uint16_t th_win; // 窗口大小
    uint16_t th_sum; // 校验和
    uint16_t th_urp; // 紧急指针
};

#define IS_SET(a, b) ((a) & (b)) ? 1 : 0
void handle_tcp(QList<QStandardItem*>* row, const struct sniff_tcp* tcp, uint16_t size);
void handle_tcp_fill(QString* infoStr, const struct sniff_tcp* tcp, uint16_t size);

#endif // TCP_H
