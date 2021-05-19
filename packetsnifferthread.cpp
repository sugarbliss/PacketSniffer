#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pfring.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <time.h>

#include <QDebug>
#include <QHash>
#include <QDataStream>
#include <QFile>
#include <QFileDialog>
#include <QStandardPaths>
#include "ethernet.h"
#include "modelcolumnindexes.h"
#include "packetsnifferthread.h"
#include "mainwindow.h"

#include "colors.h"
#include "shared.h"
#include "tags.h"

const int kPfingMaxPackerSize = 65536;

PacketSnifferThread::PacketSnifferThread(QStandardItemModel* packetModel, QStatusBar* statusBar, QString device_name, QString bpf_filter)
{
    this->packetModel = packetModel;
    this->statusBar = statusBar;
    stopCapture = false;
    packetNumber = 0;
    rawDataView = Binary;
    captureSaved = false;
    device = device_name.toStdString();
    bpfFilter = bpf_filter.toStdString();
}

PacketSnifferThread::PacketSnifferThread(QStandardItemModel* packetModel, QString& filePath, QStatusBar* statusBar)
{
    this->packetModel = packetModel;
    this->statusBar = statusBar;
    stopCapture = false;
    packetNumber = 0;
    rawDataView = Binary;
    captureSaved = false;

    QHash<QString, QColor> protocolColors;
    protocolColors.insert("ARP", QColor(255, 125, 125)); // Light Red
    protocolColors.insert("DNS", QColor(183, 247, 119)); // Light Green
    protocolColors.insert("HTTP", QColor(150, 255, 255)); // Light Cyan
    protocolColors.insert("HTTPS", QColor(121, 201, 201)); // Dark Cyan
    protocolColors.insert("ICMP", QColor(232, 209, 255)); // Light Purple
    protocolColors.insert("TCP", QColor(218, 112, 214)); // 兰花的紫色
    protocolColors.insert("UDP", QColor(0, 255, 255)); // 青色
    protocolColors.insert("Unknown", QColor(255, 253, 140)); // Light Yellow

    QFile file(filePath);
    if (!(file.open(QIODevice::ReadOnly))) {
        statusBar->showMessage(QString("Couldn't open %1").arg(filePath));
        return;
    }
    QDataStream packetStream(&file);

    qint32 packetCount;
    packetStream.readRawData((char*)&packetCount, sizeof(qint32));

    char* dateTime;
    uint timeLen;
    char* packetInfo;
    char* newData;
    qint32 packetSize;
    for (int i = 0; i < packetCount; ++i) {

        QList<QStandardItem*> row;
        QStandardItem* packetNumberItem = new QStandardItem();
        packetNumberItem->setData(QVariant(packetNumber), Qt::DisplayRole);
        row.append(packetNumberItem);
        packetNumber++;
        packetStream.readBytes(dateTime, timeLen); // 同时读取数据包到达时间，和长度
        QString str = QString::fromLocal8Bit(dateTime, timeLen); //可处理汉字
        row.append(new QStandardItem(str));
        packetStream.readRawData((char*)&packetSize, sizeof(qint32));
        packetInfo = new char[packetSize] { 0 };
        newData = new char[packetSize] { 0 };
        if (newData == nullptr || packetInfo == nullptr) {
            statusBar->showMessage(QString("Failed to apply for memory!"));
            exit(1);
        }
        packetStream.readRawData(packetInfo, packetSize); // 同时读取数据包内容，和长度
        memcpy(newData, (void*)packetInfo, packetSize);
        rawData.push_back(newData);
        if (packetInfo != nullptr)
            handle_ethernet(&row, (uint8_t*)packetInfo);
        // 某些协议尚未实现，因此有时此函数将返回并且该行将具有
        // 少于6列，如果是这种情况，则在行中附加“未知”
        while (row.size() < 6) {
            row.append(new QStandardItem("Unknown"));
        }

        QStandardItem* binaryDataSizeItem = new QStandardItem();
        binaryDataSizeItem->setData(QVariant(packetSize), Qt::DisplayRole);
        row.insert(BINARY_DATA_SIZE_COLUMN_INDEX, binaryDataSizeItem);

        if (protocolColors.contains(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text())) {
            setBackgroundColor(&row, protocolColors.value(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text()));
        }
        packetModel->appendRow(row);
    }
}

PacketSnifferThread::~PacketSnifferThread()
{
    for (size_t i = 0; i < rawData.size(); i++) {
        free(rawData.at(i));
    }

    rawData.clear();
}

void PacketSnifferThread::stopCapturing(void) {
    stopCapture = true;
}

void PacketSnifferThread::run()
{

    // 设置协议的颜色
    QHash<QString, QColor> protocolColors;
    protocolColors.insert("ARP", QColor(255, 125, 125)); //Light Red
    protocolColors.insert("DNS", QColor(183, 247, 119)); //Light Green
    protocolColors.insert("TCP", QColor(218, 112, 214)); // 兰花的紫色
    protocolColors.insert("UDP", QColor(0, 255, 255)); // 青色
    protocolColors.insert("HTTP", QColor(150, 255, 255)); //Light Cyan
    protocolColors.insert("HTTPS", QColor(121, 201, 201)); //Dark Cyan
    protocolColors.insert("ICMP", QColor(232, 209, 255)); //Light Purple
    protocolColors.insert("Unknown", QColor(255, 253, 140)); //Light Yellow

    pfring* handle;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 networkNumber; //32 bit MAC 地址
    bpf_u_int32 networkMask; //32 bit MAC 掩码
    struct pfring_pkthdr header;
    uint8_t* data = nullptr;
    uint8_t temp_buffer[kPfingMaxPackerSize];
    data = temp_buffer;
    captureSaved = false;
    // 获取设备的网络地址和网络掩码
    if (pcap_lookupnet(device.c_str(), &networkNumber, &networkMask, errorBuffer) == -1) {
        statusBar->showMessage(QString("Can't get netmask for device %1, %2").arg(QString(device.c_str())).arg(QString(errorBuffer)));
        networkNumber = 0;
        networkMask = 0;
    }

    // 获取设备的句柄，以混杂模式打开pfring
    handle = pfring_open(device.c_str(), 1500, PF_RING_PROMISC); // 混杂模式打开
    if (handle == nullptr) {
        statusBar->showMessage(QString("Couldn't open device %1").arg(QString(device.c_str())));
        return;
    }

    // 设置BPF过滤器

    char* bpffilter = (char*)bpfFilter.data();
    if (!bpfFilter.empty()) {
        if (pfring_set_bpf_filter(handle, bpffilter)) {
            statusBar->showMessage(QString("Failed to set BPF filter"));
            return;
        }
    }


    // 启用pfring
    pfring_enable_ring(handle);
    int returnValue;

    // 当有数据包时，该函数返回一个捕获的数据包
    while ((returnValue = pfring_recv(handle, &data, kPfingMaxPackerSize, &header, 0)) >= 0 && stopCapture == false) {
        if (returnValue > 0) {
            // 获取此数据包收到的时间
            tm tmp_time;
            char date_time[64] = { 0 };
            strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&header.ts.tv_sec, &tmp_time));

            // Linux终端打印时间
            printf(CYAN "	Time:\n" RESET);
            printf("		Y/M/D h:m:s -- %s\n", date_time);
            printf("		Microseconds --- %ld\n", header.ts.tv_usec);

            timeStamps.push_back(date_time);
            QList<QStandardItem*> row;

            // 将当前数据包的序号添加到界面栏
            QStandardItem* packetNumberItem = new QStandardItem();
            packetNumberItem->setData(QVariant(packetNumber), Qt::DisplayRole);
            row.append(packetNumberItem);

            // 将当前数据包的时间添加到界面栏
            row.append(new QStandardItem(QString(date_time)));

            printf(GREEN "Recieved packet #%d\n" NORMAL, packetNumber);

            packetNumber++;

            // 转到以太网层解析
            handle_ethernet(&row, data);

            // 某些协议尚未实现，因此有时此函数将返回并且该行将具有
            // 少于6列，如果是这种情况，则在行中附加“未知”
            while (row.size() < 6) {
                row.append(new QStandardItem("Unknown"));
            }

            char* newData = new char[handle->caplen] { 0 };
            if (newData == nullptr) {
                statusBar->showMessage(QString("Failed to apply for memory!"));
                exit(1);
            }
            memcpy(newData, (void*)data, header.caplen);

            // 将捕获的数据包大小添加到界面栏
            QStandardItem* binaryDataSizeItem = new QStandardItem();
            binaryDataSizeItem->setData(QVariant(header.caplen), Qt::DisplayRole);
            row.insert(BINARY_DATA_SIZE_COLUMN_INDEX, binaryDataSizeItem);
            rawData.push_back(newData);

            // 设置数据包的颜色以区别于其他数据包
            if (protocolColors.contains(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text())) {
                setBackgroundColor(&row, protocolColors.value(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text()));
            }

            packetModel->appendRow(row);
        }
    }
    if (returnValue == -1) {
        printf(RED "An error occured while capturing.\n" RESET);
    }

    stopCapture = false;

    // 关闭之前打开的pfring设备
    pfring_close(handle);
}

void PacketSnifferThread::fillInfoAndRawDataWidgets(QPlainTextEdit* infoTextEdit, QPlainTextEdit* rawDataTextEdit, int index, int size)
{
    // 添加数据包的概要信息
    QString infoStr;

    handle_ethernet_fill(&infoStr, rawData.at(index));
    infoTextEdit->clear();
    infoTextEdit->appendHtml(infoStr);

    // 添加数据包的原始数据信息
    rawDataTextEdit->clear();
    QString rawDataText;

    // 二进制数据包信息
    if (rawDataView == Binary) {
        for (int i = 0; i < size; i++) {
            uint8_t byte = rawData.at(index)[i];
            uint8_t mask = 0x80; //1000 0000
            while (mask > 0) {
                rawDataText.append((byte & mask) ? '1' : '0');
                mask >>= 1;
            }
            rawDataText.append(' ');
        }
    }
    // 十六进制数据包信息
    else if (rawDataView == Hexadecimal) {
        char hexBuffer[3];
        for (int i = 0; i < size; i++) {
            snprintf(hexBuffer, sizeof(hexBuffer), "%02X", ((uint8_t*)rawData.at(index))[i]);
            rawDataText.append(hexBuffer);
            rawDataText.append(' ');
        }
    }

    rawDataTextEdit->appendHtml(rawDataText);
}

void PacketSnifferThread::setRawDataView(RawDataView rawDataView)
{
    this->rawDataView = rawDataView;
}

bool PacketSnifferThread::saveCapture(QString filePath)
{
    if (captureSaved == true) {
        return false;
    }

    QFile saveFile(filePath);
    if (saveFile.open(QFile::WriteOnly) == false) { // 打开文件失败
        return false;
    }
    if (saveFile.exists() && saveFile.isWritable()) {
        QDataStream byteStream(&saveFile);
        // 文件已打开，将每一个数据包写入文件中
        qint32 count = rawData.size();
        byteStream.writeRawData((char*)&count, sizeof(qint32)); // 数据包个数

        for (uint32_t i = 0; i < count; i++) {
            // 将数据包的大小和接收日期写入文件
            qint32 size = packetModel->data(packetModel->index(i, BINARY_DATA_SIZE_COLUMN_INDEX)).toInt();
            QString time = QString(timeStamps[i]);
            QByteArray btArrayTime = time.toUtf8();
            byteStream.writeBytes(btArrayTime, btArrayTime.length()); // 日期
            byteStream.writeRawData((char*)&size, sizeof(qint32)); // 数据包个数
            byteStream.writeRawData(rawData[i], size);
        }
        captureSaved = true;
    } else {
        return false;
    }

    return true;
}

std::vector<std::string> PacketSnifferThread::get_device_list()
{
    pfring_if_t* dev = pfring_findalldevs();
    std::vector<std::string> ans;
    while (dev != nullptr) {
        ans.push_back(dev->name);
        dev = dev->next;
    }
    return ans;
}
