#include "mainwindow.h"
#include <QApplication>
#include <QDesktopWidget>
#include <QStyle>

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("Packet Sniffer");

    w.setGeometry(
        QStyle::alignedRect(
            Qt::LeftToRight, // 从左到右的布局
            Qt::AlignCenter, // 在可用空间中水平居中
            w.size(),
            a.desktop()->availableGeometry() // 返回带有索引屏幕的屏幕的可用几何形状
            ));

    w.show();
    return a.exec();
}
