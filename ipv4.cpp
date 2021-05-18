#include "ipv4.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include "colors.h"
#include "icmp.h"
#include "ipprotocols.h"
#include "shared.h"
#include "tags.h"
#include "tcp.h"
#include "udp.h"

void handle_ipv4(QList<QStandardItem*>* row, const struct sniff_ipv4* ip)
{
    uint32_t size_ip;

    size_ip = IP_HL(ip) * 4; // ipv4头部大小

    printf(CYAN "	IPv4 Header:\n" RESET);
    // 如果ip头部大小，小于20个字节，则将其丢弃（IP头部20 bytes）
    if (size_ip < 20) {
        printf(RED "		Invalid IP header length: %u bytes\n" NORMAL,
            size_ip);
        return;
    }

    // IP头部信息
    char addressBuffer[INET_ADDRSTRLEN];
    printf("		IP version --- IPv%d\n", IP_V(ip));
    printf("		Header Len --- %d bytes\n", IP_HL(ip) * 4);
    printf("		TOS + ECN ---- ");
    printBinaryuint8_t(ip->ip_tos);
    printf("\n		Total Length - %d bytes\n", ntohs(ip->ip_len));
    printf("		Offset ------- %d bytes\n", IP_OFFSET(ip) * 8);
    printf("		Flags+Offset - 0x%04X\n", ip->ip_off);
    printf("		TTL ---------- %d\n", ip->ip_ttl);
    printf("		Checksum ----- 0x%04X\n", ntohs(ip->ip_sum));
    printf("		Source ------- %s\n",
        inet_ntop(AF_INET, &ip->ip_src, addressBuffer, INET_ADDRSTRLEN));
    row->append(new QStandardItem(QString(addressBuffer)));
    printf("		Destination -- %s\n",
        inet_ntop(AF_INET, &ip->ip_dst, addressBuffer, INET_ADDRSTRLEN));
    row->append(new QStandardItem(QString(addressBuffer)));
    printf("		Protocol ----- %u ", ip->ip_p);

    // 确定传输层协议
    switch (ip->ip_p) {
    case IP_TCP: {
        printf("(TCP)\n");
        handle_tcp(row,
            (struct sniff_tcp*)(((char*)ip) + size_ip),
            ntohs(ip->ip_len) - size_ip);
        break;
    }
    case IP_UDP: {
        printf("(UDP)\n");
        handle_udp(row, (struct sniff_udp*)(((char*)ip) + size_ip));
        break;
    }
    case IPV4_ICMP: {
        printf("(ICMP)\n");
        handle_icmp(row, (uint8_t*)ip + size_ip, ntohs(ip->ip_len) - size_ip);
        break;
    }
    default: {
        printf(YELLOW "(Not implemented yet)" RESET "\n");
        break;
    }
    }
}

void handle_ipv4_fill(QString* infoStr, const struct sniff_ipv4* ip)
{
    uint32_t size_ip = IP_HL(ip) * 4; // ipv4的头部大小

    infoStr->append(HEADER_TAG_START "IPv4 Header:" HEADER_TAG_END NEWLINE);

    if (size_ip < 20) { // 如果大小小于20个字节，则将其丢弃（IP头部20 bytes）
        infoStr->append(TAB ERROR_TAG_START + QString("Invalid IP header length: %1 bytes").arg(size_ip) + ERROR_TAG_END NEWLINE);
        return;
    }

    // IP头部的概要信息
    char addressBuffer[INET_ADDRSTRLEN];

    infoStr->append(TAB + QString(BOLD_TAG_START "IP version" BOLD_TAG_END " --- IPv%1").arg(IP_V(ip)) + NEWLINE);

    infoStr->append(
        TAB + QString(BOLD_TAG_START "Header Len" BOLD_TAG_END " --- %1 bytes").arg(size_ip) + NEWLINE);

    infoStr->append(TAB + QString(BOLD_TAG_START "TOS + ECN" BOLD_TAG_END " ---- %1").arg(strBinaryuint8_t(ip->ip_tos)) + NEWLINE);

    infoStr->append(
        TAB + QString(BOLD_TAG_START "Total Len" BOLD_TAG_END " ---- %1 bytes").arg(ntohs(ip->ip_len)) + NEWLINE);

    infoStr->append(
        TAB + QString(BOLD_TAG_START "Offset" BOLD_TAG_END " ------- %1 bytes").arg(IP_OFFSET(ip) * 8) + NEWLINE);

    char flagsOffsetBuffer[5];
    snprintf(flagsOffsetBuffer, sizeof(flagsOffsetBuffer), "%04X", ip->ip_off);
    infoStr->append(TAB + QString(BOLD_TAG_START "Flags+Offset" BOLD_TAG_END " - 0x%1").arg(flagsOffsetBuffer) + NEWLINE);

    infoStr->append(TAB + QString(BOLD_TAG_START "TTL" BOLD_TAG_END " ---------- %1").arg(ip->ip_ttl) + NEWLINE);

    char checksumBuffer[5];
    snprintf(checksumBuffer, sizeof(checksumBuffer), "%04X", ntohs(ip->ip_sum));
    infoStr->append(TAB + QString(BOLD_TAG_START "Checksum" BOLD_TAG_END " ----- 0x%1").arg(checksumBuffer) + NEWLINE);

    infoStr->append(
        TAB + QString(BOLD_TAG_START "Source" BOLD_TAG_END " ------- %1").arg(inet_ntop(AF_INET, &ip->ip_src, addressBuffer, INET_ADDRSTRLEN)) + NEWLINE);

    infoStr->append(
        TAB + QString(BOLD_TAG_START "Destination" BOLD_TAG_END " -- %1").arg(inet_ntop(AF_INET, &ip->ip_dst, addressBuffer, INET_ADDRSTRLEN)) + NEWLINE);

    infoStr->append(
        TAB + QString(BOLD_TAG_START "Protocol" BOLD_TAG_END " ----- %1").arg(ip->ip_p));

    // 确定传输层协议
    switch (ip->ip_p) {
    case IP_TCP: {
        infoStr->append("(TCP)" NEWLINE);
        handle_tcp_fill(infoStr,
            (struct sniff_tcp*)(((char*)ip) + size_ip),
            ntohs(ip->ip_len) - size_ip);
        break;
    }
    case IP_UDP: {
        infoStr->append("(UDP)" NEWLINE);
        handle_udp_fill(infoStr, (struct sniff_udp*)(((char*)ip) + size_ip));
        break;
    }
    case IPV4_ICMP: {
        infoStr->append("(ICMP)" NEWLINE);
        handle_icmp_fill(
            infoStr, (uint8_t*)ip + size_ip, ntohs(ip->ip_len) - size_ip);
        break;
    }
    default: {
        infoStr->append(YELLOW_FONT_START
            "(Not implemented yet)" YELLOW_FONT_END NEWLINE);
        break;
    }
    }
}
