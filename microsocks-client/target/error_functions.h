/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2022.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU Lesser General Public License as published   *
* by the Free Software Foundation, either version 3 or (at your option)   *
* any later version. This program is distributed without any warranty.    *
* See the files COPYING.lgpl-v3 and COPYING.gpl-v3 for details.           *
\*************************************************************************/

/* error_functions.h

   Header file for error_functions.c.
*/


// 在标准错误设备上打印当前 errno 值相对应的错误文本
// 其中包括了错误名（比如，EPERM）以及由 strerror()返回的错误描述
void errMsg(const char *format, ...);

#ifdef __GNUC__

    /* This macro stops 'gcc -Wall' complaining that "control reaches
       end of non-void function" if we use the following functions to
       terminate main() or some other non-void function. */

#define NORETURN __attribute__ ((__noreturn__))
#else
#define NORETURN
#endif

// errExit()函数的操作方式与 errMsg()相似，只是还会终止程序
// 其一，调用 exit()退出。其二，若将环境变量 EF_DUMPCORE 定义为非空字符串
// 则调用 abort()退出，生成核心转储（core dump）文件，供调试器调试之用
// 转储文件通常在进程工作目录
void errExit(const char *format, ...) NORETURN ;

// err_exit()类似于 errExit()，但存在两方面的差异
// 打印错误消息之前，err_exit()不会刷新标准输出
// err_exit()终止进程使用的是_exit()，而非 exit()。这一退出方式，略去了对 stdio 缓冲区
// 的刷新以及对退出处理程序（exit handler）的调用
void err_exit(const char *format, ...) NORETURN ;

// errExitEN()函数与 errExit()大体相同，区别仅仅在于：与 errExit()打印与当前
// errno 值相对应的错误文本不同，errExitEN()只会打印与 errnum 参数中给定的错误号
void errExitEN(int errnum, const char *format, ...) NORETURN ;

// 这个函数基本上和使用printf没有太多不同，除了会自动追加换行符
// 作用：在标准错误输出一般性的错误信息，然后终止程序
// 优点：少写代码
// 范围：一般性错误消息，未设置 errno 的库函数错误
void fatal(const char *format, ...) NORETURN ;

// 函数 usageErr()用来诊断命令行参数使用方面的错误
// 其参数列表风格与 printf()相同，并在标准错误上打印字符串“Usage：
// 随之以格式化输出，然后调用 exit()终止程序
void usageErr(const char *format, ...) NORETURN ;

// 函数 cmdLineErr()酷似 usageErr()，但其错误诊断是针对于特定程序的命令行参数
void cmdLineErr(const char *format, ...) NORETURN ;

