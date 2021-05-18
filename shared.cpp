#include <stdint.h>
#include <stdio.h>

#include "shared.h"

void printBinaryuint8_t(uint8_t byte)
{
    uint8_t mask = 0x80; // 1000 0000
    // 打印出“byte”的二进制表示形式，没有换行符
    while (mask > 0) {
        putchar((byte & mask) ? '1' : '0');
        mask >>= 1;
    }
}

// 打印出“ byte”的二进制表示形式，没有换行符
void printBinaryuint16_t(uint16_t byte2)
{
    uint16_t mask = 0x8000; // 1000 0000 0000 0000

    uint8_t n = 1; // 在每4位之间放置一个空格的计数器
    while (mask > 0) {
        putchar((byte2 & mask) ? '1' : '0');
        mask >>= 1;
        if ((n & 0x03) == 0) { // (n & 0x03) is equivelant to (n % 4)
            putchar(' ');
        }
        n++;
    }
}

//打印出short的二进制表示形式，
//但为值<开始和值>结束打印点
//用于显示uint16_t中的当前标志
// For example:
//      byte2 ----- 10010001 00001101
//      start ----- 3
//      end ------- 6;
//      printed --- "...1000.........", 没有引号，没有换行符
void printBinaryuint16_tdots(uint16_t byte2, int start, int end)
{
    int i = 0;

    while (i < start) {
        putchar('.');
        i++;
    }

    uint16_t mask = 0x8000;
    mask >>= start;
    while (i <= end) {
        putchar((byte2 & mask) ? '1' : '0');
        mask >>= 1;
        i++;
    }

    while (i <= 15) {
        putchar('.');
        i++;
    }
}

const char* strBinaryuint16_tdots(uint16_t byte2, int start, int end)
{
    static char buffer[17];
    int i = 0;

    while (i < start) {
        buffer[i] = '.';
        i++;
    }

    uint16_t mask = 0x8000;
    mask >>= start;
    while (i <= end) {
        buffer[i] = (byte2 & mask) ? '1' : '0';
        mask >>= 1;
        i++;
    }

    while (i <= 15) {
        buffer[i] = '.';
        i++;
    }

    buffer[16] = '\0';
    return buffer;
}

const char* strBinaryuint8_t(uint8_t byte)
{
    static char buffer[9];
    uint8_t mask = 0x80; // 1000 0000
        // 将“byte”的二进制表示形式转换为字符串
    int i = 0;
    while (mask > 0) {
        buffer[i] = (byte & mask) ? '1' : '0';
        i++;
        mask >>= 1;
    }
    buffer[8] = '\0';
    return buffer;
}

void setBackgroundColor(QList<QStandardItem*>* row, QColor color)
{
    for (int i = 0; i < row->length(); ++i) {
        row->at(i)->setData(color, Qt::BackgroundColorRole);
    }
}

QString getHTMLentity(char c)
{
    QHash<char, QString> htmlEntities;
    htmlEntities.insert('<', "&lt;");
    htmlEntities.insert('>', "&gt;");

    if (htmlEntities.contains(c)) {
        return htmlEntities.value(c);
    } else {
        return QString(c);
    }
}
