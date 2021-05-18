/**************************************************************************************
该程序的执行过程：
1.接收数据包，将其解释为sniff_ethernet结构，然后调用适当的函数来处理该数据包。
2.打印出有关它的信息。
3.确定网络层协议，调用适当的函数进行处理。
4.打印出该网络层数据包的信息。
5.确定传输层协议，调用适当的函数进行处理。
6.打印出此传输层段的信息。
7.确定应用层协议，调用适当的函数进行处理。
8.打印出此应用程序级别协议的信息。
**************************************************************************************/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <colors.h>
#include <pcap.h>
#include <time.h>

#include "ethernet.h"

int main(int argc, char** argv)
{
    printf(RESET);
    if (argc != 2) {
        printf("USAGE: sniff <device>\n");
        exit(1);
    }

    char* device = argv[1]; // 要捕获的网卡设备
    pcap_t* handle; // pcap句柄
    char errorBuffer[PCAP_ERRBUF_SIZE]; // 将错误信息存储在缓冲区
    char* filterExpression = "port 53"; // 过滤器表达式
    struct bpf_program filterProgram; // 获得已编译的过滤器表达式
    bpf_u_int32 networkNumber; // 32位网络地址
    bpf_u_int32 networkMask; // 32位网络掩码

    printf("Sniffing packets on device: %s\n", device);

    // 获取设备的网络地址和网络掩码
    if (pcap_lookupnet(device, &networkNumber, &networkMask, errorBuffer) == -1) {
        fprintf(stderr, "Can't get netmask for device %s, %s\n", device, errorBuffer);
        networkNumber = 0;
        networkMask = 0;
    }

    // 获取设备的句柄，以混杂模式打开会话
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errorBuffer);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s, %s\n", device, errorBuffer);
        return 2;
    }

    pcap_loop(handle, -1, handle_ethernet, NULL);
    pcap_close(handle);

    return 0;
}