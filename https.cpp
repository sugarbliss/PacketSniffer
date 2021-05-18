
#include "https.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include "colors.h"
#include "shared.h"
#include "tags.h"

void handle_https(QList<QStandardItem*>* row, const uint8_t* https,
    uint16_t size)
{
    row->append(new QStandardItem("HTTPS"));
    printf(CYAN "	HTTPS:\n" RESET);

    if (size == 0) {
        printf("		This packet contains no more data\n");
        row->append(new QStandardItem("Acknowledgement, no more data"));
        return;
    }
    int totalLengthCounter = 0;
    QString infoStr;
    do {
        uint8_t type = https[0];
        uint16_t version = ntohs(((uint16_t*)(https + 1))[0]);
        uint16_t length = ntohs(((uint16_t*)(https + 1))[1]);

        totalLengthCounter += 5;

        printf("		Content Type - ");
        switch (type) {
        case SSL_CTYPE_HANDSHAKE: {
            printf("[22] Handshake\n");
            infoStr += "[22] Handshake, ";
            break;
        }
        case SSL_CTYPE_APP_DATA: {
            printf("[23] Application Data\n");
            infoStr += "[23] Application Data, ";
            break;
        }
        default: {
            printf(YELLOW "Content type [%u] not yet implemented.\n" RESET,
                version);
            row->append(new QStandardItem(
                QString("Content type [%1] not implemented yet").arg(version)));
            return;
        }
        }

        printf("		Version ------ ");
        switch (version) {
        case SSL_VERSION_TLSV12: {
            printf("TLSv1.2\n");
            break;
        }
        default: {
            printf(YELLOW "SSL version [0x%04X] not yet implemented." RESET "\n",
                version);
            break;
        }
        }

        printf("		Total Length - %u\n", length);

        char* data = (char*)https + 5;
        printf("		Encrypted Data:\n");

        uint16_t i = 0; // 数据索引
        int n = 1;
        printf("\t\t\t");

        while (i < length && totalLengthCounter < size) {
            char c = data[i];
            putchar(IS_PRINTABLE(c) ? c : '.');
            if (n == 64) {
                printf("\n\t\t\t");
                n = 0;
            }
            n++;
            i++;
        }

        totalLengthCounter += i;
        https = (uint8_t*)(data + i);
        putchar('\n');
    } while (totalLengthCounter < size);
    row->append(new QStandardItem(infoStr));
}

void handle_https_fill(QString* infoStr, const uint8_t* https, uint16_t size)
{
    infoStr->append(HEADER_TAG_START "HTTPS:" HEADER_TAG_END NEWLINE);

    if (size == 0) {
        infoStr->append(TAB "This packet contains no more data" NEWLINE);
        return;
    }
    int totalLengthCounter = 0;

    do {
        uint8_t type = https[0];
        uint16_t version = ntohs(((uint16_t*)(https + 1))[0]);
        uint16_t length = ntohs(((uint16_t*)(https + 1))[1]);

        totalLengthCounter += 5;

        infoStr->append(TAB BOLD_TAG_START "Content Type" BOLD_TAG_END " - ");
        switch (type) {
        case SSL_CTYPE_HANDSHAKE: {
            infoStr->append("[22] Handshake" NEWLINE);
            break;
        }
        case SSL_CTYPE_APP_DATA: {
            infoStr->append("[23] Application Data" NEWLINE);
            break;
        }
        default: {
            infoStr->append(
                QString(YELLOW_FONT_START
                    "Content type [%1] not yet implemented." YELLOW_FONT_END
                        NEWLINE)
                    .arg(version));
            return;
        }
        }

        infoStr->append(TAB BOLD_TAG_START "Version" BOLD_TAG_END " ------ ");
        switch (version) {
        case SSL_VERSION_TLSV12: {
            infoStr->append("TLSv1.2" NEWLINE);
            break;
        }
        default: {
            char versionBuffer[5];
            snprintf(versionBuffer, sizeof(versionBuffer), "%04X", version);
            infoStr->append(
                QString(YELLOW_FONT_START
                    "SSL version [0x%1] not yet implemented." YELLOW_FONT_END
                        NEWLINE)
                    .arg(versionBuffer));
            break;
        }
        }

        infoStr->append(
            QString(TAB BOLD_TAG_START "Total Length" BOLD_TAG_END " - %1" NEWLINE)
                .arg(length));
        char* data = (char*)https + 5; // Skip the header
        infoStr->append(TAB BOLD_TAG_START "Encrypted Data:" BOLD_TAG_END NEWLINE);

        uint16_t i = 0;
        int n = 1;
        infoStr->append(TAB TAB);

        while (i < length && totalLengthCounter < size) {
            char c = data[i];
            if (IS_PRINTABLE(c)) {
                infoStr->append(getHTMLentity(c));
            } else {
                infoStr->append('.');
            }
            if (n == 32) {
                infoStr->append(NEWLINE TAB TAB);
                n = 0;
            }
            n++;
            i++;
        }

        totalLengthCounter += i;
        https = (uint8_t*)(data + i);
        infoStr->append(NEWLINE);
    } while (totalLengthCounter < size);
}
