#include "dns.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include "colors.h"
#include "shared.h"
#include "tags.h"

void handle_dns(QList<QStandardItem*>* row, const struct sniff_dns* dns)
{
    uint16_t id = ntohs(dns->dh_id);
    uint16_t flags = ntohs(dns->dh_flags);
    uint16_t questionCount = ntohs(dns->dh_question_count);
    uint16_t answerCount = ntohs(dns->dh_answer_count);
    uint16_t nameServerCount = ntohs(dns->dh_name_server_count);
    uint16_t additionalRecordCount = ntohs(dns->dh_additional_record_count);

    printf(CYAN "	DNS:\n" RESET);
    row->append(new QStandardItem("DNS"));
    printf("		ID ----------- 0x%X\n", id);
    printf("		Flags:");

    QString infoString;

    infoString += "id: " + QString::number(id) + ", ";

    // 响应 or 应答?
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 0, 0);
    if (DH_IS_RESPONSE(flags)) {
        printf("Response");
        infoString += "Response, ";
    } else {
        printf("Query");
        // infoString += "Query";
    }

    // 操作码
    uint16_t opcode = DH_OPCODE(flags);
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 1, 4);
    switch (opcode) {
    case DH_OPCODE_QUERY: {
        if (DH_IS_RESPONSE(flags) == false) {
            infoString += "Standard Query, ";
        }
        printf(" Standard Query");
        break;
    }
    case DH_OPCODE_IQUERY: {
        printf(" Inverse Query");
        break;
    }
    case DH_OPCODE_STATUS: {
        printf(" Status Query");
        break;
    }
    case DH_OPCODE_RESERVED: {
        printf(" Unnasigned operation code");
        break;
    }
    case DH_OPCODE_NOTIFY: {
        printf(" Notify Query");
        break;
    }
    case DH_OPCODE_UPDATE: {
        printf(" Update Query");
        break;
    }
    default: {
        printf(YELLOW " Operation code %u unknown" RESET, opcode);
        break;
    }
    }

    // 权威标志位
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 5, 5);
    if (DH_IS_AUTHORITATIVE(flags)) {
        printf(" Authoritative");
    } else {
        printf(" Not authoritative");
    }

    // 截断标志位
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 6, 6);
    if (DH_IS_TRUNC(flags)) {
        printf(" Truncated");
    } else {
        printf(" Not truncated");
    }

    // 期望递归标志位
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 7, 7);
    if (DH_REC_DESIRED(flags)) {
        printf(" Recursion desired");
    } else {
        printf(" Recursion not desired");
    }

    // 递归可用标志位
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 8, 8);
    if (DH_REC_AVAILABLE(flags)) {
        printf(" Recursion available");
    } else {
        printf(" Recursion not available");
    }

    // 保留标志位
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 9, 11);
    if (DH_RESERVED(flags)) {
        printf(RED " Reserved bits not zeroed" RESET);
    } else {
        printf(" Reserved bits zeroed (as they should be)");
    }

    // 回应操作码
    uint16_t rcode = DH_RCODE(flags);
    printf("\n\t\t\t");
    printBinaryuint16_tdots(flags, 12, 15);
    switch (rcode) {
    case DH_RCODE_NO_ERR: {
        printf(" No error occured");
        break;
    }
    case DH_RCODE_FMT_ERR: {
        printf(" Format error");
        break;
    }
    case DH_RCODE_SERV_ERR: {
        printf(" Server Failure");
        break;
    }
    case DH_RCODE_NAME_ERR: {
        printf(" Non-existant domain");
        break;
    }
    case DH_RCODE_NOT_IMPL: {
        printf(" Not implemented");
        break;
    }
    case DH_RCODE_REFUSED: {
        printf(" Query refused");
        break;
    }
    default: {
        printf(YELLOW " Response code %u not implemented yet" RESET, rcode);
    }
    }

    printf("\n		Questions ---- %u\n", questionCount);
    int i;
    char* payload = ((char*)dns) + 12;
    for (i = 0; i < questionCount; i++) {
        printf("			#%d. ", i + 1); // 打印编号
        while (*payload <= 31) { // 直到获得有效的ascii字符
            payload++;
        }
        // 如果字符不是ASCII字符，则打印出一个点
        while (*payload != 0) {
            if (*payload >= 32) {
                putchar(*payload);
                infoString.append(*payload);
            } else {
                putchar('.');
                infoString.append('.');
            }
            payload++;
        }
        payload++;
        putchar('\n');
        infoString += ", ";
        payload += 4;
    }

    printf("		Answers ------ %u\n", answerCount);
    if (answerCount > 0) {
        for (i = 0; i < answerCount; i++) {
            uint16_t name = ntohs(*((uint16_t*)payload));
            payload += 2;

            uint16_t type = ntohs(*((uint16_t*)payload));
            payload += 2;

            uint16_t dnsClass = ntohs(*((uint16_t*)payload));
            payload += 2;

            uint32_t ttl = ntohl(*((uint32_t*)payload));
            payload += 4;

            uint16_t length = ntohs(*((uint16_t*)payload));
            payload += 2;

            printf("			#%d:\n", i + 1);
            printf("				Name -- ");
            char* nameptr = (char*)dns;
            if (DH_IS_POINTER(name)) {
                nameptr += DH_NAME_OFFSET(name);
            }
            while ((*nameptr) != 0) {
                name = *((uint16_t*)nameptr);
                name = ntohs(name);
                if (DH_IS_POINTER(name)) {
                    nameptr = ((char*)dns) + DH_NAME_OFFSET(name);
                }

                char c = *nameptr;
                putchar(IS_PRINTABLE(c) ? c : '.');
                infoString.append(IS_PRINTABLE(c) ? c : '.');
                nameptr++;
            }
            putchar('\n');
            infoString.append('.');
            printf("				Type -- ");
            switch (type) {
            case DH_RECORD_A: {
                if (length == 4) {
                    char address[INET_ADDRSTRLEN];
                    printf("A: %s\n",
                        inet_ntop(AF_INET, payload, address, sizeof(address)));
                    infoString += QString(address);
                }
                break;
            }
            case DH_RECORD_CNAME: {
                printf("CNAME: ");
                infoString.append("CNAME: ");
                int i = 0;
                while (i < length - 2) {
                    char c = payload[i];
                    putchar(IS_PRINTABLE(c) ? c : '.');
                    infoString.append(IS_PRINTABLE(c) ? c : '.');
                    i++;
                }
                name = *((uint16_t*)(payload + i));
                name = ntohs(name);
                if (DH_IS_POINTER(name)) {
                    char* cnameptr = (char*)dns + DH_NAME_OFFSET(name);
                    while ((*cnameptr) != 0) {
                        name = *((uint16_t*)cnameptr);
                        name = ntohs(name);
                        if (DH_IS_POINTER(name)) {
                            cnameptr = ((char*)dns) + DH_NAME_OFFSET(name);
                        }

                        char c = *cnameptr;
                        putchar(IS_PRINTABLE(c) ? c : '.');
                        infoString.append(IS_PRINTABLE(c) ? c : '.');
                        cnameptr++;
                    }
                }
                putchar('\n');
                break;
            }
            }
            printf("				Class - [%u] ", dnsClass);
            switch (dnsClass) {
            case DNS_CLASS_IN: {
                printf("(Internet)");
                break;
            }
            default: {
                printf(YELLOW " (Unknown)" RESET);
                break;
            }
            }
            putchar('\n');

            printf("				TTL --- %u seconds\n", ttl);

            printf("				Len --- %u bytes\n", length);
            payload += length;
        }
    }
    row->append(new QStandardItem(infoString));

    printf("		NS Count ----- %u\n", nameServerCount);
    printf("		AR Count ----- %u\n", additionalRecordCount);
}

void handle_dns_fill(QString* infoStr, const struct sniff_dns* dns)
{
    uint16_t id = ntohs(dns->dh_id);
    uint16_t flags = ntohs(dns->dh_flags);
    uint16_t questionCount = ntohs(dns->dh_question_count);
    uint16_t answerCount = ntohs(dns->dh_answer_count);
    uint16_t nameServerCount = ntohs(dns->dh_name_server_count);
    uint16_t additionalRecordCount = ntohs(dns->dh_additional_record_count);

    infoStr->append(HEADER_TAG_START "DNS:" HEADER_TAG_END NEWLINE);

    char idBuffer[5];
    snprintf(idBuffer, sizeof(idBuffer), "%X", id);
    infoStr->append(TAB + QString(BOLD_TAG_START "ID" BOLD_TAG_END " ----------- 0x%1").arg(idBuffer) + NEWLINE);

    infoStr->append(TAB BOLD_TAG_START "Flags: " BOLD_TAG_END);

    // 响应还是查询？
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 0, 0));
    if (DH_IS_RESPONSE(flags)) {
        infoStr->append(" Response");
    } else {
        infoStr->append(" Query");
    }

    // 操作码
    uint16_t opcode = DH_OPCODE(flags);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 1, 4));

    switch (opcode) {
    case DH_OPCODE_QUERY: {
        infoStr->append(" Standard Query");
        break;
    }
    case DH_OPCODE_IQUERY: {
        infoStr->append(" Inverse Query");
        break;
    }
    case DH_OPCODE_STATUS: {
        infoStr->append(" Status Query");
        break;
    }
    case DH_OPCODE_RESERVED: {
        infoStr->append(" Unnasigned operation code");
        break;
    }
    case DH_OPCODE_NOTIFY: {
        printf(" Notify Query");
        break;
    }
    case DH_OPCODE_UPDATE: {
        infoStr->append(" Update Query");
        break;
    }
    default: {
        infoStr->append(QString(YELLOW_FONT_START
            " Operation code %1 unknown" YELLOW_FONT_END)
                            .arg(opcode));
        break;
    }
    }

    // 权威标志位
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 5, 5));
    if (DH_IS_AUTHORITATIVE(flags)) {
        infoStr->append(" Authoritative");
    } else {
        infoStr->append(" Not authoritative");
    }

    // 截断标志位
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 6, 6));
    if (DH_IS_TRUNC(flags)) {
        infoStr->append(" Truncated");
    } else {
        infoStr->append(" Not truncated");
    }

    // 期望递归标志位
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 7, 7));
    if (DH_REC_DESIRED(flags)) {
        infoStr->append(" Recursion desired");
    } else {
        infoStr->append(" Recursion not desired");
    }

    // 递归可用标志位
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 8, 8));
    if (DH_REC_AVAILABLE(flags)) {
        infoStr->append(" Recursion available");
    } else {
        infoStr->append(" Recursion unavailable");
    }

    // 保留标志位
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 9, 11));
    if (DH_RESERVED(flags)) {
        infoStr->append(" Reserved bits not zeroed");
    } else {
        infoStr->append(" Reserved bits zeroed");
    }

    // 回应操作码
    uint16_t rcode = DH_RCODE(flags);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 12, 15));
    switch (rcode) {
    case DH_RCODE_NO_ERR: {
        infoStr->append(" No error occured");
        break;
    }
    case DH_RCODE_FMT_ERR: {
        infoStr->append(" Format error");
        break;
    }
    case DH_RCODE_SERV_ERR: {
        infoStr->append(" Server Failure");
        break;
    }
    case DH_RCODE_NAME_ERR: {
        infoStr->append(" Non-existant domain");
        break;
    }
    case DH_RCODE_NOT_IMPL: {
        infoStr->append(" Not implemented");
        break;
    }
    case DH_RCODE_REFUSED: {
        infoStr->append(" Query refused");
        break;
    }
    default: {
        infoStr->append(
            QString(YELLOW_FONT_START
                " Response code %1 not implemented yet" YELLOW_FONT_END)
                .arg(rcode));
    }
    }

    infoStr->append(QString(NEWLINE TAB BOLD_TAG_START "Questions" BOLD_TAG_END
                                                       " ---- %1" NEWLINE)
                        .arg(questionCount));
    int i;
    char* payload = ((char*)dns) + 12;
    for (i = 0; i < questionCount; i++) {
        infoStr->append(TAB TAB + QString("#%1. ").arg(i + 1));
        while (*payload <= 31) { // 直到获得有效的ascii字符
            payload++;
        }
        // 如果字符不是ASCII字符，则打印出一个点
        while (*payload != 0) {
            if (*payload >= 32) {
                infoStr->append(*payload);
            } else {
                infoStr->append('.');
            }
            payload++;
        }
        payload++;
        infoStr->append(NEWLINE);
        payload += 4;
    }

    infoStr->append(
        QString(TAB BOLD_TAG_START "Answers" BOLD_TAG_END " ------ %1" NEWLINE)
            .arg(answerCount));
    if (answerCount > 0) {
        for (i = 0; i < answerCount; i++) {
            uint16_t name = ntohs(*((uint16_t*)payload));
            payload += 2;

            uint16_t type = ntohs(*((uint16_t*)payload));
            payload += 2;

            uint16_t dnsClass = ntohs(*((uint16_t*)payload));
            payload += 2;

            uint32_t ttl = ntohl(*((uint32_t*)payload));
            payload += 4;

            uint16_t length = ntohs(*((uint16_t*)payload));
            payload += 2;

            infoStr->append(
                QString(TAB TAB BOLD_TAG_START "#%1:" BOLD_TAG_END NEWLINE)
                    .arg(i + 1));

            infoStr->append(TAB TAB TAB BOLD_TAG_START "Name" BOLD_TAG_END " -- ");

            char* nameptr = (char*)dns;
            if (DH_IS_POINTER(name)) {
                nameptr += DH_NAME_OFFSET(name);
            }
            while ((*nameptr) != 0) {
                name = *((uint16_t*)nameptr);
                name = ntohs(name);
                if (DH_IS_POINTER(name)) {
                    nameptr = ((char*)dns) + DH_NAME_OFFSET(name);
                }

                char c = *nameptr;
                infoStr->append(IS_PRINTABLE(c) ? c : '.');
                nameptr++;
            }
            infoStr->append(NEWLINE);

            infoStr->append(TAB TAB TAB BOLD_TAG_START "Type" BOLD_TAG_END " -- ");

            switch (type) {
            case DH_RECORD_A: {
                if (length == 4) {
                    char address[INET_ADDRSTRLEN];
                    infoStr->append(QString("A: %1" NEWLINE)
                                        .arg(inet_ntop(AF_INET, payload, address,
                                            sizeof(address))));
                }
                break;
            }
            case DH_RECORD_CNAME: {
                infoStr->append("CNAME: ");
                int i = 0;
                while (i < length - 2) {
                    char c = payload[i];
                    infoStr->append(IS_PRINTABLE(c) ? c : '.');
                    i++;
                }
                name = *((uint16_t*)(payload + i));
                name = ntohs(name);
                if (DH_IS_POINTER(name)) {
                    char* cnameptr = (char*)dns + DH_NAME_OFFSET(name);
                    while ((*cnameptr) != 0) {
                        name = *((uint16_t*)cnameptr);
                        name = ntohs(name);
                        if (DH_IS_POINTER(name)) {
                            cnameptr = ((char*)dns) + DH_NAME_OFFSET(name);
                        }

                        char c = *cnameptr;
                        infoStr->append(IS_PRINTABLE(c) ? c : '.');
                        cnameptr++;
                    }
                }
                infoStr->append(NEWLINE);
                break;
            }
            }
            infoStr->append(
                QString(TAB TAB TAB BOLD_TAG_START "Class" BOLD_TAG_END " - [%1] ")
                    .arg(dnsClass));
            switch (dnsClass) {
            case DNS_CLASS_IN: {
                infoStr->append("(Internet)");
                break;
            }
            default: {
                infoStr->append(YELLOW_FONT_START " (Unknown)" YELLOW_FONT_END);
                break;
            }
            }
            infoStr->append(NEWLINE);

            infoStr->append(QString(TAB TAB TAB BOLD_TAG_START
                "TTL" BOLD_TAG_END " --- %1 seconds" NEWLINE)
                                .arg(ttl));

            infoStr->append(QString(TAB TAB TAB BOLD_TAG_START
                "Len" BOLD_TAG_END " --- %1 bytes" NEWLINE)
                                .arg(length));
            payload += length;
        }
    }

    infoStr->append(
        QString(TAB BOLD_TAG_START "NS Count" BOLD_TAG_END " ----- %1" NEWLINE)
            .arg(nameServerCount));
    infoStr->append(
        QString(TAB BOLD_TAG_START "AR Count" BOLD_TAG_END " ----- %1" NEWLINE)
            .arg(additionalRecordCount));
}
