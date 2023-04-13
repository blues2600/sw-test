/*
 *
 * microsocks的客户端程序
 *
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "error_functions.h"

#define BUF_SIZE 1024

// 连接到一个服务器，IP和端口是固定的
// 成功返回服务器套接字描述符，失败退出程序
int ConnectHost() {
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        errExit("socket");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(7777);

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)))
        errExit("connect");

    printf("[*] successfully connected to server.\n");
    return fd;
}

// 向服务器发送用户名和密码，以通过服务器对客户端的身份验证
void SendUserPassword(int fd) {
    /* 根据check_credentials发送身份验证数据
     * 缓冲区长度必须大于5个字节，缓冲区第一个字节为0x1
     * 缓冲区第二个字节是用户名长度，接着是用户名
     * 用户名的后面一个字节是密码长度，然后是密码
     * 接着是端口号（占用两个字节），实际上，端口号只占用一个字节，即最后一个字节*/

    ssize_t bytes_write = 0;
    char user_pass[] = {'\x1', '\x5', 'a', 'd', 'm', 'i', 'n', '\x8',
                        'a',   'd',   'm', 'i', 'n', '1', '2', '3'};
    bytes_write = write(fd, user_pass, strlen(user_pass));
    if (bytes_write != strlen(user_pass))
        errExit("write");
}

// 文本ip转换为二进制ip
void SendTargetInfo(int fd) {
    char head[100] = {'\x5', '\x1', '\x0', '\x1'};
    char ip[] = "127.0.0.1";

    /* ip字符串首先被转换为in_addr类型，得到的值实际是一个无符号32位整数
     * 再将这个整数从低字节依次放入head
     */
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) <= 0)
        errExit("inet_pton");
    char *p = (char *)&addr.s_addr;
    head[4] = *p;  // ip
    head[5] = *(p + 1);
    head[6] = *(p + 2);
    head[7] = *(p + 3);
    head[8] = 0x0;  // port 5888
    head[8] = 0x17;

    ssize_t bytes_write = write(fd, head, 10);  // ipv4至少发送10字节
    if (bytes_write != 10)
        errExit("write");
}

// 套接字消息循环，本机发送流量到服务器，服务器发送到target，回传信息的路径也一样
void MessageLoop(int fd) {
    char buf[BUF_SIZE] = {'\0'};
    ssize_t bytes_read = 0;
    ssize_t bytes_write = 0;

    fd_set master, workset;
    FD_ZERO(&master);
    FD_SET(fd, &master);
    FD_SET(STDOUT_FILENO, &master);
    int max_fd = fd > STDOUT_FILENO ? fd : STDOUT_FILENO;

    while (1) {
        FD_ZERO(&workset);
        memcpy(&workset, &master, sizeof(master));
        if (select(max_fd + 1, &workset, NULL, NULL, NULL) <= 0)
            errExit("select");

        if (FD_ISSET(fd, &workset)) {
            bytes_read = read(fd, buf, BUF_SIZE);
            if (bytes_read == 0)
                errExit("read");
            if (bytes_read == -1)
                errExit("read");

            bytes_write = write(STDOUT_FILENO, buf, bytes_read);
            if (bytes_write != bytes_read)
                errExit("write");
        }

        if (FD_ISSET(STDOUT_FILENO, &workset)) {
            bytes_read = read(STDOUT_FILENO, buf, BUF_SIZE);
            if (bytes_read == 0)
                errExit("read");
            if (bytes_read == -1)
                errExit("read");

            bytes_write = write(fd, buf, bytes_read);
            if (bytes_write != bytes_read)
                errExit("write");
        }
    }
}

// 客户端和代理服务器交互，以验证用户的身份
void UserAuthentication(int fd) {
    char buf[BUF_SIZE] = {'\0'};
    ssize_t bytes_read = 0;

    fd_set master, workset;
    FD_ZERO(&master);
    FD_SET(fd, &master);
    int max_fd = fd;

    while (1) {
        FD_ZERO(&workset);
        memcpy(&workset, &master, sizeof(master));
        if (select(max_fd + 1, &workset, NULL, NULL, NULL) <= 0)
            errExit("select");

        if (FD_ISSET(fd, &workset)) {
            bytes_read = read(fd, buf, BUF_SIZE);
            if (bytes_read == 0)
                errExit("read");
            if (bytes_read == -1)
                errExit("read");

            /* 验证消息是否为版本号 + 身份验证方式代码
             * 5是版本号，2是身份验证方式代码，意味着使用用户名和密码向服务器证明身份*/
            if (buf[0] == 0x5 && buf[1] == 0x2)
                SendUserPassword(fd);

            /* 验证身份是否通过，如验证通过，根据connect_socks_target的协议发送希望连接的target
             * 发送的内容缓冲区长度必须大于5，缓冲区第一个字节必须为0x5
             * 缓冲区第二个字节必须为0x1，缓冲区第三个字节必须为0x0
             * 第四个字节标识缓冲区5~N字节的内容类别
             * 若第四个字节为0x4则意味着后续内容为ipv6，若为0x1则意味着后续内容为ipv4
             * 若为0x3则意味着后续内容为dns name
             */
            if (buf[0] == 0x1 && buf[1] == 0x0)
                SendTargetInfo(fd);

            /* 验证是否连接上target ,根据send_error中的协议来判断
             * char success_connect_target[10] = { 5, 0, 0, 1 , 0,0,0,0, 0,0
             * };
             * */
            if (buf[0] == 0x5 && buf[1] == 0x0) {
                printf("[*] successfully connected to target.\n");
                MessageLoop(fd);
                exit(0);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    /* 根据microsocks的协议来发送数据（check_auth_method函数内定义）
     * 第一个字节是0x5，第二个字节为0x2，第三个字节指定身份验证模式，这里指定为0x2*/
    char buf[] = {'\x5', '\x2', '\x2'};
    int fd = ConnectHost();
    write(fd, buf, 3);

    UserAuthentication(fd);

    close(fd);
    return 0;
}

