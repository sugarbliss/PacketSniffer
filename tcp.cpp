#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "http.h"
#include "https.h"
#include "ports.h"
#include "tcp.h"

#include "colors.h"
#include "shared.h"
#include "tags.h"

void handle_tcp(QList<QStandardItem*>* row, const struct sniff_tcp* tcp, uint16_t size)
{
    uint8_t size_tcp = TH_OFF(tcp) << 2;

    printf(CYAN "	TCP Header:\n" RESET);
    if (size_tcp < 20) {
        printf(RED "		Invalid TCP header length: %u bytes\n" NORMAL, size_tcp);
        return;
    }
    uint16_t sourcePort = ntohs(tcp->th_sport);
    uint16_t destinationPort = ntohs(tcp->th_dport);
    uint32_t sequenceNumber = ntohl(tcp->th_seq);
    uint32_t ackNumber = ntohl(tcp->th_ack);

    printf("		Source port -- %u\n", sourcePort);
    printf("		Dest. port --- %u\n", destinationPort);
    printf("		Seq. # ------- %u\n", sequenceNumber);
    printf("		Ack Number --- %u\n", ackNumber);
    printf("		Offset ------- %u bytes\n", size_tcp);
    printf("		Payload ------ %u bytes\n", size - size_tcp);

    printf("		Flags:");
    if (IS_SET(tcp->th_flags, TH_CWR)) {
        printf(" CWR");
    }
    if (IS_SET(tcp->th_flags, TH_ECE)) {
        printf(" ECE");
    }
    if (IS_SET(tcp->th_flags, TH_URG)) {
        printf(" URG");
    }
    if (IS_SET(tcp->th_flags, TH_ACK)) {
        printf(" ACK");
    }
    if (IS_SET(tcp->th_flags, TH_PSH)) {
        printf(" PSH");
    }
    if (IS_SET(tcp->th_flags, TH_RST)) {
        printf(" RST");
    }
    if (IS_SET(tcp->th_flags, TH_SYN)) {
        printf(" SYN");
    }
    if (IS_SET(tcp->th_flags, TH_FIN)) {
        printf(" FIN");
    }

    putchar('\n');
    printf("			CWR %d.......\n", IS_SET(tcp->th_flags, TH_CWR));
    printf("			ECE .%d......\n", IS_SET(tcp->th_flags, TH_ECE));
    printf("			URG ..%d.....\n", IS_SET(tcp->th_flags, TH_URG));
    printf("			ACK ...%d....\n", IS_SET(tcp->th_flags, TH_ACK));
    printf("			PSH ....%d...\n", IS_SET(tcp->th_flags, TH_PSH));
    printf("			RST .....%d..\n", IS_SET(tcp->th_flags, TH_RST));
    printf("			SYN ......%d.\n", IS_SET(tcp->th_flags, TH_SYN));
    printf("			FIN .......%d\n", IS_SET(tcp->th_flags, TH_FIN));
    printf("		Window ------- %u\n", ntohs(tcp->th_win));
    printf("		Checksum ----- 0x%04X\n", ntohs(tcp->th_sum));

    const char* payload = ((char*)tcp) + size_tcp;
    bool portFound = false;

    switch (destinationPort) {
    case PORT_HTTP: {
        handle_http(row, payload, size - size_tcp);
        portFound = true;
        break;
    }
    case PORT_HTTPS: {
        handle_https(row, (uint8_t*)payload, size - size_tcp);
        portFound = true;
        break;
    }
    default: {
        row->append(new QStandardItem("TCP"));
        QString infoString;
        infoString = "Port " + QString::number(sourcePort, 10) + " port " + QString::number(destinationPort, 10) + " communication";
        row->append(new QStandardItem(infoString));
        portFound = true;
    }
    }
    if (portFound == false) {
        switch (sourcePort) {
        case PORT_HTTP: {
            handle_http(row, payload, size - size_tcp);
            break;
        }
        case PORT_HTTPS: {
            handle_https(row, (uint8_t*)payload, size - size_tcp);
            break;
        }
        default: {
            printf(YELLOW "	Application layer protocol [%d] not implemented yet." RESET "\n", destinationPort);
            row->append(new QStandardItem("TCP"));
            QString infoString;
            infoString = "Port " + QString::number(sourcePort, 10) + " port " + QString::number(destinationPort, 10) + " communication";
            row->append(new QStandardItem(infoString));
        }
        }
    }
}

void handle_tcp_fill(QString* infoStr, const struct sniff_tcp* tcp, uint16_t size)
{
    uint8_t size_tcp = TH_OFF(tcp) << 2; // TCP头部大小

    infoStr->append(HEADER_TAG_START "TCP Header:" HEADER_TAG_END NEWLINE);
    if (size_tcp < 20) {
        infoStr->append(QString(TAB ERROR_TAG_START "Invalid TCP header length: %1 bytes" ERROR_TAG_END NEWLINE).arg(size_tcp));
        return;
    }

    uint16_t sourcePort = ntohs(tcp->th_sport);
    uint16_t destinationPort = ntohs(tcp->th_dport);
    uint32_t sequenceNumber = ntohl(tcp->th_seq);
    uint32_t ackNumber = ntohl(tcp->th_ack);

    infoStr->append(QString(TAB BOLD_TAG_START "Source port" BOLD_TAG_END " -- %1" NEWLINE).arg(sourcePort));

    infoStr->append(QString(TAB BOLD_TAG_START "Dest. port" BOLD_TAG_END " --- %1" NEWLINE).arg(destinationPort));

    infoStr->append(QString(TAB BOLD_TAG_START "Seq. #" BOLD_TAG_END " ------- %1" NEWLINE).arg(sequenceNumber));

    infoStr->append(QString(TAB BOLD_TAG_START "Ack Number" BOLD_TAG_END " --- %1" NEWLINE).arg(ackNumber));

    infoStr->append(QString(TAB BOLD_TAG_START "Offset" BOLD_TAG_END " ------- %1 bytes" NEWLINE).arg(size_tcp));

    infoStr->append(QString(TAB BOLD_TAG_START "Payload" BOLD_TAG_END " ------ %1 bytes" NEWLINE).arg(size - size_tcp));

    infoStr->append(TAB BOLD_TAG_START "Flags:" BOLD_TAG_END);
    if (IS_SET(tcp->th_flags, TH_CWR)) {
        infoStr->append(" CWR");
    }
    if (IS_SET(tcp->th_flags, TH_ECE)) {
        infoStr->append(" ECE");
    }
    if (IS_SET(tcp->th_flags, TH_URG)) {
        infoStr->append(" URG");
    }
    if (IS_SET(tcp->th_flags, TH_ACK)) {
        infoStr->append(" ACK");
    }
    if (IS_SET(tcp->th_flags, TH_PSH)) {
        infoStr->append(" PSH");
    }
    if (IS_SET(tcp->th_flags, TH_RST)) {
        infoStr->append(" RST");
    }
    if (IS_SET(tcp->th_flags, TH_SYN)) {
        infoStr->append(" SYN");
    }
    if (IS_SET(tcp->th_flags, TH_FIN)) {
        infoStr->append(" FIN");
    }

    infoStr->append(NEWLINE);

    infoStr->append(QString(TAB TAB BOLD_TAG_START "CWR " BOLD_TAG_END "%1......." NEWLINE).arg(IS_SET(tcp->th_flags, TH_CWR)));

    infoStr->append(QString(TAB TAB BOLD_TAG_START "ECE " BOLD_TAG_END ".%1......" NEWLINE).arg(IS_SET(tcp->th_flags, TH_ECE)));

    infoStr->append(QString(TAB TAB BOLD_TAG_START "URG " BOLD_TAG_END "..%1....." NEWLINE).arg(IS_SET(tcp->th_flags, TH_URG)));

    infoStr->append(QString(TAB TAB BOLD_TAG_START "ACK " BOLD_TAG_END "...%1...." NEWLINE).arg(IS_SET(tcp->th_flags, TH_ACK)));

    infoStr->append(QString(TAB TAB BOLD_TAG_START "PSH " BOLD_TAG_END "....%1..." NEWLINE).arg(IS_SET(tcp->th_flags, TH_PSH)));

    infoStr->append(QString(TAB TAB BOLD_TAG_START "RST " BOLD_TAG_END ".....%1.." NEWLINE).arg(IS_SET(tcp->th_flags, TH_RST)));

    infoStr->append(QString(TAB TAB BOLD_TAG_START "SYN " BOLD_TAG_END "......%1." NEWLINE).arg(IS_SET(tcp->th_flags, TH_SYN)));

    infoStr->append(QString(TAB TAB BOLD_TAG_START "FIN " BOLD_TAG_END ".......%1" NEWLINE).arg(IS_SET(tcp->th_flags, TH_FIN)));

    infoStr->append(QString(TAB BOLD_TAG_START "Window" BOLD_TAG_END " ------- %1" NEWLINE).arg(ntohs(tcp->th_win)));

    char checksumBuffer[5];
    snprintf(checksumBuffer, sizeof(checksumBuffer), "%04X", ntohs(tcp->th_sum));
    infoStr->append(QString(TAB BOLD_TAG_START "Checksum" BOLD_TAG_END " ----- 0x%1" NEWLINE).arg(checksumBuffer));

    const char* payload = ((char*)tcp) + size_tcp;
    bool portFound = false;

    switch (destinationPort) {
    case PORT_HTTP: {
        handle_http_fill(infoStr, payload, size - size_tcp);
        portFound = true;
        break;
    }
    case PORT_HTTPS: {
        handle_https_fill(infoStr, (uint8_t*)payload, size - size_tcp);
        portFound = true;
        break;
    }
    }

    if (portFound == false) {
        switch (sourcePort) {
        case PORT_HTTP: {
            handle_http_fill(infoStr, payload, size - size_tcp);
            break;
        }
        case PORT_HTTPS: {
            handle_https_fill(infoStr, (uint8_t*)payload, size - size_tcp);
            break;
        }
        default: {
            infoStr->append(TAB YELLOW_FONT_START "Application layer protocols not implemented yet" YELLOW_FONT_END NEWLINE);
        }
        }
    }
}
