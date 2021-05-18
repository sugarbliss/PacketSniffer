#ifndef ICMP_H
#define ICMP_H

#include <netinet/ip_icmp.h>
#include <stdint.h>

#include <QList>
#include <QStandardItem>

struct sniff_icmp {
    u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_cksum;
    union {
        u_char ih_pptr;
        struct in_addr ih_gwaddr;
        struct ih_idseq {
            u_int16_t icd_id;
            u_int16_t icd_seq;
        } ih_idseq;
        u_int32_t ih_void;

        struct ih_pmtu {
            u_int16_t ipm_void;
            u_int16_t ipm_nextmtu;
        } ih_pmtu;

        struct ih_rtradv {
            u_int8_t irt_num_addrs;
            u_int8_t irt_wpa;
            u_int16_t irt_lifetime;
        } ih_rtradv;
    } sniff_icmp_hun;
    union {
        struct {
            u_int32_t its_otime; // 请求包发起时间戳
            u_int32_t its_rtime; // 应答包接收时间戳
            u_int32_t its_ttime; // 应答包传送时间戳
        } id_ts;
        struct {
            struct ip idi_ip;
            /* 选项，64位数据 */
        } id_ip;
        struct icmp_ra_addr id_radv;
        u_int32_t id_mask;
        u_int8_t id_data[1];
    } sniff_icmp_dun;
};

// ICMP类型和操作码
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_DEST_UNREACH 3

#define ICMP_CODE_DEST_UNREACH_NET 0
#define ICMP_CODE_DEST_UNREACH_HOST 1
#define ICMP_CODE_DEST_UNREACH_PRO 2
#define ICMP_CODE_DEST_UNREACH_PORT 3

#define ICMP_TYPE_TRACEROUTE 30

void handle_icmp(QList<QStandardItem*>* row, const uint8_t* data,
    uint16_t length);
void handle_icmp_fill(QString* infoStr, const uint8_t* data, uint16_t length);

void printTimestamp(QString* infoStr, time_t seconds, time_t ms);
QString getTimeStamp(time_t seconds, time_t ms);

#endif // ICMP_H
