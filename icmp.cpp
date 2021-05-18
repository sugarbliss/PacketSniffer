#include "icmp.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "colors.h"
#include "shared.h"
#include "tags.h"

// icmp回显（ping）请求/答复的时间戳是一个整数，表示自时间段以来的毫秒数

void handle_icmp(QList<QStandardItem*>* row, const uint8_t* data,
    uint16_t length)
{
    const struct sniff_icmp* icmp;
    icmp = (struct sniff_icmp*)data;
    uint8_t type = icmp->icmp_type;
    uint8_t code = icmp->icmp_code;
    uint16_t checksum = ntohs(icmp->icmp_cksum);

    uint16_t offset = 4;

    printf(CYAN "	ICMP:\n" RESET);
    row->append(new QStandardItem("ICMP"));

    QString infoStr;

    printf("		Type --------- [%u] ", type);
    switch (type) {
    case ICMP_TYPE_ECHO_REPLY: {
        printf("Echo reply\n");
        infoStr += "Echo Reply, ";
        time_t seconds = icmp->sniff_icmp_dun.id_ts.its_otime;
        time_t ms = icmp->sniff_icmp_dun.id_ts.its_ttime;
        printTimestamp(&infoStr, seconds, ms);
        break;
    }
    case ICMP_TYPE_ECHO_REQUEST: {
        printf("Echo request\n");
        infoStr += "Echo Request, ";
        time_t seconds = icmp->sniff_icmp_dun.id_ts.its_otime;
        time_t ms = icmp->sniff_icmp_dun.id_ts.its_ttime;
        printTimestamp(&infoStr, seconds, ms);
        break;
    }
    case ICMP_TYPE_DEST_UNREACH: {
        printf("Destination unreachable\n");
        infoStr += "Destination unreachable";
        break;
    }
    default: {
        printf(YELLOW "Unknown type\n" RESET);
        break;
    }
    }

    row->append(new QStandardItem(infoStr));

    printf("		Code --------- [%u]\n", code);
    printf("		Checksum ----- 0x%04X\n", checksum);
    printf("		Data:\n\t\t\t");

    data += offset;
    uint16_t n = 0; // Used for newlines
    while (offset < length) {
        if (n == 4) {
            printf("\n\t\t\t");
            n = 0;
        }
        printBinaryuint8_t(*data);
        putchar(' ');
        data++;
        n++;
        offset++;
    }

    putchar('\n');
}

void handle_icmp_fill(QString* infoStr, const uint8_t* data, uint16_t length)
{
    const struct sniff_icmp* icmp;
    icmp = (struct sniff_icmp*)data;
    uint8_t type = icmp->icmp_type;
    uint8_t code = icmp->icmp_code;
    ;
    uint16_t checksum = ntohs(icmp->icmp_cksum);
    uint16_t offset = 4;

    infoStr->append(QString(HEADER_TAG_START "ICMP:" HEADER_TAG_END NEWLINE));

    infoStr->append(
        QString(TAB BOLD_TAG_START "Type" BOLD_TAG_END " --------- [%1] ")
            .arg(type));
    switch (type) {
    case ICMP_TYPE_ECHO_REPLY: {
        infoStr->append("Echo reply" NEWLINE);
        time_t seconds = icmp->sniff_icmp_dun.id_ts.its_rtime;
        infoStr->append(TAB BOLD_TAG_START "Timestamp ---- " BOLD_TAG_END);
        infoStr->append(getTimeStamp(seconds, 0));
        infoStr->append(NEWLINE);
        break;
    }
    case ICMP_TYPE_ECHO_REQUEST: {
        infoStr->append("Echo request" NEWLINE);
        time_t seconds = icmp->sniff_icmp_dun.id_ts.its_otime;
        infoStr->append(TAB BOLD_TAG_START "Timestamp ---- " BOLD_TAG_END);
        infoStr->append(getTimeStamp(seconds, 0));
        infoStr->append(NEWLINE);
        break;
    }
    case ICMP_TYPE_DEST_UNREACH: {
        infoStr->append("Destination unreachable" NEWLINE);
        break;
    }
    default: {
        infoStr->append(YELLOW_FONT_START "Unknown type" YELLOW_FONT_END NEWLINE);
        break;
    }
    }

    infoStr->append(
        QString(TAB BOLD_TAG_START "Code" BOLD_TAG_END " --------- [%1]" NEWLINE)
            .arg(code));
    char checksumBuffer[5];
    snprintf(checksumBuffer, sizeof(checksumBuffer), "%04X", checksum);
    infoStr->append(
        QString(TAB BOLD_TAG_START "Checksum" BOLD_TAG_END " ----- 0x%1" NEWLINE)
            .arg(checksumBuffer));
    infoStr->append(TAB BOLD_TAG_START "Data:" BOLD_TAG_END NEWLINE TAB TAB);

    data += offset;
    uint16_t n = 0; // 用于换行
    while (offset < length) {
        if (n == 4) {
            infoStr->append(NEWLINE TAB TAB);
            n = 0;
        }
        infoStr->append(strBinaryuint8_t(*data));
        infoStr->append(' ');
        data++;
        n++;
        offset++;
    }
}

void printTimestamp(QString* infoStr, time_t seconds, time_t ms)
{
    char* datetime = ctime(&seconds);
    datetime[strlen(datetime) - 1] = '\0';

    int i = strlen(datetime);
    while (datetime[i] != ' ') { // 查找最后一个空格的索引
        i--;
    }
    printf("		Timestamp ---- ");
    int j = 0;
    while (j < i) {
        putchar(datetime[j]);
        infoStr->append(datetime[j]);
        j++;
    }

    printf(".%u%s\n", (uint32_t)ms, datetime + i);
    infoStr->append(QString("%2").arg(QString(datetime + i)));
}

QString getTimeStamp(time_t seconds, time_t ms)
{
    char* datetime = ctime(&seconds);
    datetime[strlen(datetime) - 1] = '\0';

    QString timeString;

    int i = strlen(datetime);
    while (datetime[i] != ' ') { // 查找最后一个空格的索引
        i--;
    }

    int j = 0;
    while (j < i) {
        timeString.append(datetime[j]);
        j++;
    }

    timeString.append(QString("%2").arg(QString(datetime + i)));
    return timeString;
}
