#include "mainwindow.h"


#include <stdio.h>
#include <stdlib.h>

#include <QDebug>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QRegExp>
#include <QStandardItem>
#include <QStandardPaths>

#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    packetModel = new QStandardItemModel(0, 7, this);
    packetModel->setHorizontalHeaderItem(PACKET_NUMBER_COLUMN_INDEX,
        new QStandardItem("#"));
    packetModel->setHorizontalHeaderItem(TIME_RECIEVED_COLUMN_INDEX,
        new QStandardItem("Time"));
    packetModel->setHorizontalHeaderItem(SOURCE_ADDRESS_COLUMN_INDEX,
        new QStandardItem("Src"));
    packetModel->setHorizontalHeaderItem(DESTINATION_ADDRESS_COLUMN_INDEX,
        new QStandardItem("Dest"));
    packetModel->setHorizontalHeaderItem(BINARY_DATA_SIZE_COLUMN_INDEX,
        new QStandardItem("Size"));
    packetModel->setHorizontalHeaderItem(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX,
        new QStandardItem("Pro"));
    packetModel->setHorizontalHeaderItem(INFORMATION_COLUMN_INDEX,
        new QStandardItem("Info"));

    packetModelProxy = new QSortFilterProxyModel(this);
    packetModelProxy->setSourceModel(packetModel);
    ui->packetTableView->setModel(packetModelProxy);
    ui->packetInfoTextArea->setWordWrapMode(QTextOption::NoWrap);
    ui->packetTableView->resizeColumnsToContents();
    ui->packetTableView->verticalHeader()->setMaximumSectionSize(
        ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->setDefaultSectionSize(
        ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->hide();
    ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    isCapturing = false;
    ui->startCaptureButton->setEnabled(true);
    ui->pauseCaptureButton->setEnabled(false);
    ui->deleteCaptureButton->setEnabled(false);

    packetSnifferThread = NULL;
    isSaved = false;
    auto device = packetSnifferThread->get_device_list();

    for (auto iter : device) {
        ui->combo_box_device_names->addItem(QString::fromStdString(iter));
    }
    // 默认值为0。如果值为-1，则将从所有列中读取键。
    packetModelProxy->setFilterKeyColumn(-1);
    connect(ui->syntaxComboBox, SIGNAL(currentIndexChanged(int)), this,
        SLOT(select_filter_mode()));
    connect(ui->searchLineEdit, SIGNAL(textChanged(QString)), this,
        SLOT(select_filter_mode()));
    connect(ui->enable_match_case, SIGNAL(stateChanged(int)), this,
        SLOT(select_filter_mode()));

    connect(ui->filterlineEdit, SIGNAL(textChanged(QString)), this,
        SLOT(get_filter_text()));

    if (ui->searchLineEdit->text().length() != 0) {
        ui->statusBar->showMessage(QString("%1 packet(s) containing the text '%2'")
                                       .arg(packetModelProxy->rowCount())
                                       .arg(ui->searchLineEdit->text()));
    }
    resize(1000, 600);
}

MainWindow::~MainWindow()
{
    if (packetSnifferThread != NULL) {
        packetSnifferThread->stopCapturing();
        while (packetSnifferThread->isRunning()) {
        }
        delete packetSnifferThread;
    }
    delete ui;
    delete packetModel;
}

void MainWindow::on_startCaptureButton_clicked()
{
    // 如果这是第一个捕获，或者如果删除了先前的捕获，则创建一个新的PacketSnifferThread
    if (packetSnifferThread == NULL) {
        packetSnifferThread = new PacketSnifferThread(
            packetModel, ui->statusBar, ui->combo_box_device_names->currentText(), filter);
    }

    // 禁用和启用相关按钮
    ui->startCaptureButton->setEnabled(false);
    ui->pauseCaptureButton->setEnabled(true);
    ui->deleteCaptureButton->setEnabled(false);

    // 启用抓包线程
    packetSnifferThread->start();
    ui->statusBar->showMessage(QString("Packet capture started."));

    // 此捕获不再保存
    isSaved = false;
}

void MainWindow::on_pauseCaptureButton_clicked()
{
    // 停止抓包线程
    packetSnifferThread->stopCapturing();
    ui->statusBar->showMessage(QString("Packet capture paused."));

    // 禁用和启用相关按钮
    ui->startCaptureButton->setEnabled(true);
    ui->pauseCaptureButton->setEnabled(false);
    if (packetModel->rowCount() > 0) {
        ui->deleteCaptureButton->setEnabled(true);
    } else {
        ui->deleteCaptureButton->setEnabled(false);
    }
}

void MainWindow::on_actionResize_Columns_triggered()
{
    for (int i = 0; i < packetModel->columnCount() - 1; i++) {
        ui->packetTableView->resizeColumnToContents(i);
        ui->statusBar->showMessage(QString("Rows resized to fit data."));
    }
}

void MainWindow::on_packetTableView_clicked(const QModelIndex& index)
{
    QModelIndex mappedIndex = packetModelProxy->mapToSource(index);
    int rawDataIndex = packetModel
                           ->data(packetModel->index(mappedIndex.row(),
                               PACKET_NUMBER_COLUMN_INDEX))
                           .toInt();
    int size = packetModel
                   ->data(packetModel->index(mappedIndex.row(),
                       BINARY_DATA_SIZE_COLUMN_INDEX))
                   .toInt();
    packetSnifferThread->fillInfoAndRawDataWidgets(
        ui->packetInfoTextArea, ui->packetRawTextEdit, rawDataIndex, size);
    ui->packetInfoTextArea->moveCursor(QTextCursor::Start);
}

void MainWindow::select_filter_mode()
{
    QRegExp::PatternSyntax syntax = QRegExp::PatternSyntax(ui->syntaxComboBox->currentIndex());
    QRegExp regExp;
    if (ui->enable_match_case->isChecked()) {
        // 读取用于过滤源模型内容的键的列。
        QRegExp regExp(ui->searchLineEdit->text(), Qt::CaseSensitive, syntax); // 区分大小写
        packetModelProxy->setFilterRegExp(regExp);
    } else {
        QRegExp regExp(ui->searchLineEdit->text(), Qt::CaseInsensitive, syntax); // 不区分大小写
        packetModelProxy->setFilterRegExp(regExp);
    }
}

void MainWindow::get_filter_text() {
    filter = ui->filterlineEdit->text();
}


void MainWindow::on_hexViewRawButton_clicked()
{
    if (packetSnifferThread != NULL) {
        packetSnifferThread->setRawDataView(Hexadecimal);
    }
    if (ui->packetTableView->currentIndex().isValid()) {
        ui->packetTableView->clicked(ui->packetTableView->currentIndex());
    }
}

void MainWindow::on_binViewRawButton_clicked()
{
    if (packetSnifferThread != NULL) {
        packetSnifferThread->setRawDataView(Binary);
    }
    if (ui->packetTableView->currentIndex().isValid()) {
        ui->packetTableView->clicked(ui->packetTableView->currentIndex());
    }
}

void MainWindow::on_actionSave_triggered()
{
    // 如果没有要保存的内容，则返回
    if (packetSnifferThread == NULL) {
        ui->statusBar->showMessage("There is nothing to save.");
        return;
    }

    // 如果捕获仍在运行，则返回
    if (packetSnifferThread->isRunning()) {
        ui->statusBar->showMessage("Please pause the capture first to save.");
        return;
    }

    // 如果当前捕获已保存，则返回
    if (isSaved == true) {
        ui->statusBar->showMessage("This capture is already saved.");
        return;
    }

    // 获取文件路径
    ui->statusBar->showMessage(QString("Saving capture..."));
    QString filePath = QFileDialog::getSaveFileName(
        this, "Save File",
        QStandardPaths::displayName(QStandardPaths::DesktopLocation),
        "Packet Sniffer Save (*.psnf)");

    // 如果用户单击文件对话框上的“取消”，则返回
    if (filePath.length() == 0) {
        ui->statusBar->showMessage(QString("No File Chosen."));
        return;
    }

    // 尝试保存捕获
    if (packetSnifferThread->saveCapture(filePath) == true) {
        ui->statusBar->showMessage(
            QString("File succesfully saved to %1").arg(filePath));
        isSaved = true;
    } else {
        ui->statusBar->showMessage(
            QString("Error saving file to %1").arg(filePath));
        isSaved = false;
    }
}

void MainWindow::on_actionNew_Capture_triggered()
{
    if (packetSnifferThread == NULL) { // 没有捕获正在运行，什么也没有保存
        packetSnifferThread = new PacketSnifferThread(
            packetModel, ui->statusBar, ui->combo_box_device_names->currentText(), filter);
    } else if (packetSnifferThread->isRunning()) { // 捕获仍在运行
        ui->statusBar->showMessage("Please stop the current capture.");
    } else if (isSaved == false) { // 捕获未运行，但未保存
        ui->deleteCaptureButton->click();
        if (packetSnifferThread == NULL) {
            packetSnifferThread = new PacketSnifferThread(packetModel, ui->statusBar,
                ui->combo_box_device_names->currentText(), filter);
        } 
    } else {
        ui->deleteCaptureButton->setEnabled(true);
        ui->deleteCaptureButton->click();
    }
}

void MainWindow::on_actionOpen_triggered()
{
    if (packetSnifferThread != NULL && isSaved == false) {
        if (packetSnifferThread->isRunning()) {
            ui->statusBar->showMessage("Please stop the current capture.");
            return;
        }
        ui->deleteCaptureButton->click();
    }
    QString fileName = QFileDialog::getOpenFileName(
        this, "Open File",
        QStandardPaths::displayName(QStandardPaths::DesktopLocation),
        "Packet Sniffer Save File(*.psnf);; All files(*.*)");
    // 如果用户单击“取消”，则返回
    if (fileName.length() == 0) {
        ui->statusBar->showMessage("No file selected.");
        return;
    }
    packetSnifferThread = new PacketSnifferThread(packetModel, fileName, ui->statusBar);
    isSaved = true;
}

// 仅当数据包捕获已停止时，此选项才可用。
// 调用此方法时，将删除与当前捕获关联的所有数据
// 1.删除packetSnifferThread。
// 2.删除packetModel中的每一行，当然除了标题之外。
// 3.禁用deleteCaptureButton按钮
void MainWindow::on_deleteCaptureButton_clicked()
{
    // 如果当前捕获未保存，则显示一个对话框，询问用户是否要保存或丢弃该捕获
    if (isSaved == false) {
        QMessageBox yesnobox(
            QMessageBox::Warning, "Unsaved Capture",
            "Do you want to save the current capture?",
            QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, this);
        yesnobox.setDefaultButton(QMessageBox::Cancel);

        int action = yesnobox.exec();
        if (action == QMessageBox::Save) { // 保存当前捕获
            ui->actionSave->trigger();
        } else if (action == QMessageBox::Discard) { // 放弃当前捕获
            delete packetSnifferThread;
            packetSnifferThread = NULL;
            packetModel->removeRows(0, packetModel->rowCount());
            ui->deleteCaptureButton->setEnabled(false);
            ui->statusBar->showMessage("Capture discarded.");
        }
    } else {
        delete packetSnifferThread;
        packetSnifferThread = NULL;
        packetModel->removeRows(0, packetModel->rowCount());
        ui->deleteCaptureButton->setEnabled(false);
        ui->statusBar->showMessage("Capture discarded.");
    }
}

void MainWindow::on_actionStart_triggered() { ui->startCaptureButton->click(); }

void MainWindow::on_actionPause_triggered() { ui->pauseCaptureButton->click(); }

void MainWindow::on_actionClear_triggered()
{
    ui->deleteCaptureButton->click();
}
