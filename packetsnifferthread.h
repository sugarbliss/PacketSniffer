#ifndef PACKETSNIFFERTHREAD_H
#define PACKETSNIFFERTHREAD_H

#include <vector>
#include <QPlainTextEdit>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QThread>

enum RawDataView {
    Hexadecimal,
    Binary
};

class PacketSnifferThread : public QThread {
public:
    PacketSnifferThread(QStandardItemModel* packetModel, QStatusBar* statusBar, QString device_name, QString bpf_filter);
    PacketSnifferThread(QStandardItemModel* packetModel, QString& filePath, QStatusBar* statusBar);
    ~PacketSnifferThread();

private:
    std::vector<char*> rawData; // 保留数据包的原始二进制数据
    std::vector<char*> timeStamps; // 每个数据包的时间戳
    QStandardItemModel* packetModel;
    QStatusBar* statusBar;
    bool stopCapture;
    int packetNumber;
    RawDataView rawDataView;
    bool captureSaved;
    std::string device;
    std::string bpfFilter;
    void run();

public:
    void stopCapturing();
    void fillInfoAndRawDataWidgets(QPlainTextEdit* infoTextEdit, QPlainTextEdit* rawDataTextEdit, int index, int size);
    void setRawDataView(RawDataView rawDataView);

    bool saveCapture(QString filePath);
    void saveCaptureAs(void);
    void openCapture(void);
    std::vector<std::string> get_device_list();
};

#endif // PACKETSNIFFERTHREAD_H
