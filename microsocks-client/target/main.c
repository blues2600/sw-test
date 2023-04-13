/*
 *
 *
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h> /* See NOTES */
#include <unistd.h>
#include <arpa/inet.h>

#include "error_functions.h"

#define BUF_SIZE 1024
#define LISTEN_BACKLOG 10

// 建立服务器，等待连接
// 成功返回服务器套接字描述符，失败返回-1
int build_server() {
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        errExit("socket");

    addr.sin_family = AF_INET;                 // 指定网络套接字
    addr.sin_addr.s_addr = htonl(INADDR_ANY);  // 接受所有IP地址的连接
    addr.sin_port = htons(5888);               // 绑定到9736端口

    // 端口防止阻塞设置
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        errExit("bind");

    if (listen(fd, LISTEN_BACKLOG) == -1)
        errExit("listen");

    return fd;
}

// 接受一个连接,加入监听集合，并重设maxfd
// 成功返回套接字fd，失败返回-1
int accept_connect(int listen, fd_set *list, int *maxfd) {
    int fd = accept(listen, NULL, NULL);
    if (fd < 0) {
        printf("%s %d Error:accept()\n", __FILE__, __LINE__);
        return -1;
    }
    FD_SET(fd, list);
    *maxfd = *maxfd > fd ? *maxfd : fd;
    return fd;
}

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

            bytes_write = write(fd, buf, bytes_read);
            if (bytes_write != bytes_read)
                errExit("write");
        }
    }
}

int main(int argc, char *argv[]) {
    int server = build_server();
    int client = accept(server, NULL, NULL);
    if (client == -1)
        errExit("accept");

    MessageLoop(client);
    return 0;
}
