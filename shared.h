#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

// 如果传递给此宏的字符是可打印字符，则返回非零
#define IS_PRINTABLE(c) (((c) >= 32) && ((c) <= 126))

#define MAC_ADDRESS_STRLEN 18

void printBinaryuint8_t(uint8_t byte);
void printBinaryuint16_t(uint16_t byte);

const char* strBinaryuint8_t(uint8_t byte);

void printBinaryuint16_tdots(uint16_t byte2, int start, int end);
const char* strBinaryuint16_tdots(uint16_t byte2, int start, int end);

void setBackgroundColor(QList<QStandardItem*>* row, QColor color);

QString getHTMLentity(char c);

#endif // SHARED_H
