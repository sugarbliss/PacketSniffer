#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>

#include <vector>

#include "modelcolumnindexes.h"
#include "new_window.h"
#include "packetsnifferthread.h"

/*
 * 表格格式:
 * 
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+
 * | TIME_RECIEVED_COLUMN_INDEX | SOURCE_ADDRESS_COLUMN_INDEX | DESTINATION_ADDRESS_COLUMN_INDEX | HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX | INFORMATION_COLUMN_INDEX |
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+
 * |    YYYY/MM/DD hh:mm:ss     |    IPv4/IPv6/MAC address    |     IPv4/IPv6/MAC address        |        ARP/DNS/HTTP/ICMP/etc.       | Short summary of packet  |
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+
 * |    2020/10/01 10:22:55     |         192.168.7.1         |           192.168.7.0            |                  ARP                |                          |
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+
 * 
 */


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = 0);
    ~MainWindow();

private slots:
    void on_startCaptureButton_clicked(); // 开始抓包
    void on_actionResize_Columns_triggered(); // 调整列的大小
    void on_packetTableView_clicked(const QModelIndex& index); // 点击一个数据包时显示详细信息

    void on_hexViewRawButton_clicked(); // 原始数据包视图切换为十六进制
    void on_binViewRawButton_clicked(); // 原始数据包视图切换为二进制

    void on_actionSave_triggered(); // 仅在当前捕获未运行时保存它

    void on_pauseCaptureButton_clicked();

    void on_actionNew_Capture_triggered();

    void on_actionOpen_triggered();

    void on_deleteCaptureButton_clicked();

    void on_actionStart_triggered();

    void on_actionPause_triggered();

    void on_actionClear_triggered();

    void select_filter_mode(); // 选择过滤模式

    void get_filter_text();

private:
    Ui::MainWindow* ui;
    int numPackets;
    QStandardItemModel* packetModel;
    QSortFilterProxyModel* packetModelProxy;
    PacketSnifferThread* packetSnifferThread;
    QString filter;

    bool isCapturing;
    bool isSaved;
};

#endif // MAINWINDOW_H
