#ifndef HTTP_H
#define HTTP_H

#include <QList>
#include <QStandardItem>

void handle_http(QList<QStandardItem*>* row, const char* data,
    uint16_t size); // 处理传入的数据包，填写表格行的列
void handle_http_fill(QString* infoStr, const char* data,
    uint16_t size); // 用数据包的完整摘要填写textEdit

#endif // HTTP_H
