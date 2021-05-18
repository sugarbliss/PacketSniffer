QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

LIBS += -lpcap -lpfring

SOURCES += main.cpp\
        mainwindow.cpp \
    packetsnifferthread.cpp \
    ethernet.cpp \
    arp.cpp \
    ipv4.cpp \
    shared.cpp \
    dns.cpp \
    udp.cpp \
    tcp.cpp \
    http.cpp \
    icmp.cpp \
    https.cpp \
    ipv6.cpp

HEADERS  += mainwindow.h \
    packetsnifferthread.h \
    ethernet.h \
    modelcolumnindexes.h \
    arp.h \
    ipv4.h \
    shared.h \
    ipprotocols.h \
    dns.h \
    udp.h \
    ports.h \
    tcp.h \
    http.h \
    icmp.h \
    https.h \
    ipv6.h \
    tags.h \
    colors.h

FORMS    += mainwindow.ui

RESOURCES += resources.qrc

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
