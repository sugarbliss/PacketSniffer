#include "arp.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include "colors.h"
#include "modelcolumnindexes.h"
#include "shared.h"
#include "tags.h"

void handle_arp(QList<QStandardItem*>* row, const struct sniff_arp* arp)
{
    static const char* opcodeStrings[] = { "ARP REQUEST", "ARP REPLY",
        "RARP REQUEST", "RARP RAPLY",
        "DRARP REQUEST", "DRARP REPLY",
        "DRARP ERROR", "INARP REQUEST",
        "INARP REPLY" };
    uint16_t hardwareType = ntohs(arp->ah_hardware);
    uint16_t protocolType = ntohs(arp->ah_protocol);
    uint16_t opcode = ntohs(arp->ah_opcode);

    uint8_t* data = ((uint8_t*)arp) + 8;

    printf(CYAN "	ARP:\n" RESET);

    if (opcode >= 1 && opcode <= 9) {
        printf("		Operation ---- %s\n", opcodeStrings[opcode - 1]);
    } else {
        printf(YELLOW
            "		ARP operation [%u] not implemented yet.\n" RESET,
            opcode);
        return;
    }

    switch (hardwareType) {
    case ARP_HARDWARE_TYPE_ETHERNET: {
        printf("		Hardware ----- Ethernet\n");
        break;
    }
    default: {
        printf(YELLOW
            "		ARP hardware type [%u] not implemented yet.\n" RESET,
            hardwareType);
        return;
    }
    }

    switch (protocolType) {
    case ARP_PROTOCOL_TYPE_IPV4: {
        printf("		Protocol ----- IPv4\n");
        break;
    }
    default: {
        printf(YELLOW
            "		ARP protocol type [%u] not implemented yet.\n" RESET,
            protocolType);
        return;
    }
    }

    printf("		Hardware len - %u\n", arp->ah_hlen);
    printf("		Protocol len - %u\n", arp->ah_plen);

    uint8_t* senderip = data;
    uint8_t* destinationHardware = data;
    uint8_t* destinationip = data;

    switch (arp->ah_hlen) {
    case ARP_MAC_LENGTH: {
        printf("		Sender MAC --- %02X:%02X:%02X:%02X:%02X:%02X\n",
            data[0],
            data[1],
            data[2],
            data[3],
            data[4],
            data[5]);
        senderip += ARP_MAC_LENGTH;
        break;
    }
    default: {
        printf(YELLOW
            "		Hardware length [%u] not implemented yet.\n" RESET,
            arp->ah_hlen);
        return;
    }
    }

    switch (arp->ah_plen) {
    case ARP_IPv4_LENGTH: {
        char sourceipBuffer[INET_ADDRSTRLEN];
        char destinationipBuffer[INET_ADDRSTRLEN];

        // 源IP
        inet_ntop(AF_INET,
            senderip,
            sourceipBuffer,
            sizeof(sourceipBuffer)); // 将网络字节顺序排列的IP转换为字符串IP
        printf("		Sender IP ---- %s\n", sourceipBuffer);
        row->append(new QStandardItem(QString(sourceipBuffer)));

        // 计算指向目标的MAC地址和目标ip地址的指针
        destinationHardware += arp->ah_hlen + ARP_IPv4_LENGTH;
        destinationip += arp->ah_hlen + ARP_IPv4_LENGTH + arp->ah_hlen;

        // 目的IP
        inet_ntop(
            AF_INET,
            destinationip,
            destinationipBuffer,
            sizeof(destinationipBuffer)); // 将网络字节顺序排列的IP转换为字符串IP
        printf("		Dest. MAC ---- %02X:%02X:%02X:%02X:%02X:%02X\n",
            destinationHardware[0],
            destinationHardware[1],
            destinationHardware[2],
            destinationHardware[3],
            destinationHardware[4],
            destinationHardware[5]);
        printf("		Dest. IP ----- %s\n", destinationipBuffer);
        row->append(new QStandardItem(QString(destinationipBuffer)));

        row->append(new QStandardItem("ARP"));

        QString infoString;
        if (opcode == ARP_OPCODE_REQUEST) {
            infoString = QString("Who has %1, tell %2")
                             .arg(QString(destinationipBuffer))
                             .arg(QString(sourceipBuffer));
        } else if (opcode == ARP_OPCODE_REPLY) {
            char sourceMacBuffer[18];
            snprintf(sourceMacBuffer,
                sizeof(sourceMacBuffer),
                "%02X:%02X:%02X:%02X:%02X:%02X",
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5]);
            infoString = QString("%1 is at %2")
                             .arg(QString(sourceipBuffer))
                             .arg(QString(sourceMacBuffer));
        } else {
            infoString = QString("Unknown opcode: %1").arg(opcode);
        }

        row->append(new QStandardItem(infoString));

        break;
    }
    default: {
        printf(YELLOW
            "		Network length [%u] not implemented yet.\n" RESET,
            arp->ah_plen);
        return;
    }
    }
}

void handle_arp_fill(QString* infoStr, const struct sniff_arp* arp)
{
    static const char* opcodeStrings[] = { "ARP REQUEST", "ARP REPLY",
        "RARP REQUEST", "RARP RAPLY",
        "DRARP REQUEST", "DRARP REPLY",
        "DRARP ERROR", "INARP REQUEST",
        "INARP REPLY" };
    uint16_t hardwareType = ntohs(arp->ah_hardware);
    uint16_t protocolType = ntohs(arp->ah_protocol);
    uint16_t opcode = ntohs(arp->ah_opcode);

    uint8_t* data = ((uint8_t*)arp) + 8;

    infoStr->append(HEADER_TAG_START "ARP:" HEADER_TAG_END NEWLINE);

    if (opcode >= 1 && opcode <= 9) {
        infoStr->append(QString(TAB BOLD_TAG_START "Operation" BOLD_TAG_END
                                                   " ---- %1 (%2)" NEWLINE)
                            .arg(opcode)
                            .arg(opcodeStrings[opcode - 1]));
    } else {
        infoStr->append(
            QString(TAB YELLOW_FONT_START
                "ARP operation [%1] not implemented yet." YELLOW_FONT_END NEWLINE)
                .arg(opcode));
        return;
    }

    switch (hardwareType) {
    case ARP_HARDWARE_TYPE_ETHERNET: {
        infoStr->append(QString(TAB BOLD_TAG_START "Hardware" BOLD_TAG_END
                                                   " ----- %1 (Ethernet)" NEWLINE)
                            .arg(hardwareType));
        break;
    }
    default: {
        infoStr->append(
            QString(
                TAB YELLOW_FONT_START
                "ARP hardware type [%1] not implemented yet." YELLOW_FONT_END NEWLINE)
                .arg(hardwareType));
        return;
    }
    }

    switch (protocolType) {
    case ARP_PROTOCOL_TYPE_IPV4: {
        infoStr->append(TAB BOLD_TAG_START "Protocol" BOLD_TAG_END
                                           " ----- IPv4" NEWLINE);
        break;
    }
    default: {
        infoStr->append(
            QString(
                TAB YELLOW_FONT_START
                "ARP protocol type [%1] not implemented yet." YELLOW_FONT_END NEWLINE)
                .arg(protocolType));
        return;
    }
    }

    infoStr->append(
        QString(TAB BOLD_TAG_START "Hardware len" BOLD_TAG_END " - %1" NEWLINE)
            .arg(arp->ah_hlen));

    infoStr->append(
        QString(TAB BOLD_TAG_START "Protocol len" BOLD_TAG_END " - %1" NEWLINE)
            .arg(arp->ah_plen));

    uint8_t* senderHardware = data;
    uint8_t* senderip = data;
    uint8_t* destinationHardware = data;
    uint8_t* destinationip = data;

    switch (arp->ah_hlen) {
    case ARP_MAC_LENGTH: {
        char senderMACbuffer[MAC_ADDRESS_STRLEN];
        snprintf(senderMACbuffer,
            sizeof(senderMACbuffer),
            "%02X:%02X:%02X:%02X:%02X:%02X",
            senderHardware[0],
            senderHardware[1],
            senderHardware[2],
            senderHardware[3],
            senderHardware[4],
            senderHardware[5]);

        infoStr->append(
            QString(TAB BOLD_TAG_START "Sender MAC" BOLD_TAG_END " --- %1" NEWLINE)
                .arg(senderMACbuffer));

        senderip += ARP_MAC_LENGTH;
        break;
    }
    default: {
        infoStr->append(
            QString(
                TAB YELLOW_FONT_START
                "Hardware length [%1] not implemented yet." YELLOW_FONT_END NEWLINE)
                .arg(arp->ah_hlen));
        return;
    }
    }

    switch (arp->ah_plen) {
    case ARP_IPv4_LENGTH: {
        char sourceipBuffer[INET_ADDRSTRLEN];
        char destinationipBuffer[INET_ADDRSTRLEN];
        char destinationMACbuffer[MAC_ADDRESS_STRLEN];

        inet_ntop(AF_INET,
            senderip,
            sourceipBuffer,
            sizeof(sourceipBuffer)); // 将网络字节顺序排列的IP转换为字符串IP
        infoStr->append(
            QString(TAB BOLD_TAG_START "Sender IP" BOLD_TAG_END " ---- %1" NEWLINE)
                .arg(sourceipBuffer));

        destinationHardware += arp->ah_hlen + ARP_IPv4_LENGTH;
        destinationip += arp->ah_hlen + ARP_IPv4_LENGTH + arp->ah_hlen;

        snprintf(destinationMACbuffer,
            sizeof(destinationMACbuffer),
            "%02X:%02X:%02X:%02X:%02X:%02X",
            destinationHardware[0],
            destinationHardware[1],
            destinationHardware[2],
            destinationHardware[3],
            destinationHardware[4],
            destinationHardware[5]);
        infoStr->append(
            QString(TAB BOLD_TAG_START "Dest. MAC" BOLD_TAG_END " ---- %1" NEWLINE)
                .arg(destinationMACbuffer));

        inet_ntop(AF_INET,
            destinationip,
            destinationipBuffer,
            sizeof(destinationipBuffer));
        infoStr->append(
            QString(TAB BOLD_TAG_START "Dest. IP" BOLD_TAG_END " ----- %1" NEWLINE)
                .arg(destinationipBuffer));

        break;
    }
    default: {
        infoStr->append(
            QString(TAB YELLOW_FONT_START
                "Network length [%1] not implemented yet." YELLOW_FONT_END)
                .arg(arp->ah_plen));
        return;
    }
    }
}
