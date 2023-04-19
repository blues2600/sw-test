

/*
 * 创建一个名为.crypted的 section
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ELFcrypt.h"

#define MAX_PATH_LEN 256
#define MAX_LINE_LEN 1024

CRYPTED int print_world(void) {
    printf("world\n");
    return 0;
}

unsigned long long get_proc_map_addr() {
    pid_t pid = getpid();  // 获取当前进程的进程 ID

    char path[MAX_PATH_LEN];
    snprintf(path, MAX_PATH_LEN - 1, "/proc/%d/maps",
             pid);  // 根据进程 ID 构造 maps 文件的路径

    FILE *fp = fopen(path, "r");  // 打开 /proc/<pid>/maps 文件

    if (fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LEN];
    char *start_addr_str;
    unsigned long long start_addr;

    fgets(line, MAX_LINE_LEN - 1, fp);  // 读取第一行

    start_addr_str = strtok(line, "-");  // 获取起始地址

    start_addr =
        strtoull(start_addr_str, NULL, 16);  // 将起始地址字符串转换为无符号整数

    //printf("process start address: %p\n", (void *)start_addr);

    fclose(fp);

    return start_addr;
}

void gettheoffandsize(char *file) {
    int offset = 0;
    short size = 0;
    int e_shoff = 0;
    int sh_size = 0;
    int fd = open(file, O_RDONLY);
    if (fd == -1)
        exit(EXIT_FAILURE);

    // 指向e_ident[EI_PAD]
    if (lseek(fd, 9, SEEK_SET) == -1)
        exit(EXIT_FAILURE);

    // 读取保存在elf header中的偏移量和大小
    if (read(fd, &offset, 4) == -1)
        exit(EXIT_FAILURE);

    if (read(fd, &size, 2) == -1)
        exit(EXIT_FAILURE);

    //printf("offset=%d,size=%hd\n", offset, size);
    ELFdecrypt(NULL,get_proc_map_addr(),offset,(int)size);
}

int main(int argc, char *argv[]) {
    printf("hello\n");
    gettheoffandsize(argv[0]);
    return print_world();
}
