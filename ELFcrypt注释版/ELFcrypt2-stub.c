#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

#include "ELFcrypt.h"


/* memfd_create prototype */
static inline int memfd_create(const char *name, unsigned int flags) {
  return syscall(__NR_memfd_create, name, flags);
}


/* main() -- Use the ELFappend technique to retrieve encrypted ELF then attempt
 *           to execute it in memory. I opted out of verbose error messages
 *           for this program to mask its intentions a little bit.
 *           使用ELFappend技术来获取加密的ELF文件，然后尝试在内存中执行它。
 *           我选择不显示详细错误消息，以便掩盖这个程序的意图
 */
int main(int argc, char *argv[], char *envp[]) {
  int             i;
  int             fd;
  int             in;
  size_t          offset;
  size_t          filesize;
  unsigned char   *key;
  void            *program;
  char            characters[] = \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";


  // 生成随机数种子
  /* Seed RNG */
  srand(time(NULL));

  // 计算整个文件的大小
  /* Calculate size of the stub + encrypted ELF */
  filesize = get_file_size(argv[0]);

  // offset指向加密数据的第一个字节
  /* Calculate size of the stub */
  offset = get_elf_size(argv[0]);
  if (offset == -1)
    return EXIT_FAILURE;

  // 这里打开的是argv[0]
  /* Open stub + encrypted ELF for reading, then mmap() it */
  in = open(argv[0], O_RDONLY);
  if (in == -1)
    return EXIT_FAILURE;

  // 把文件映射到内存
  program = mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, in, 0);
  if (program == MAP_FAILED)
    return EXIT_FAILURE;

  /* Skip the stub. The encrypted data lies right after the stub. */
  // 指向加密数据
  program += offset;

  // 获得本机ELFCRYPT环境变量的值，如果没有则要求用户输入
  /* Attempt to decrypt the ELF using the key supplied by the user */
  key = (unsigned char *)getenv("ELFCRYPT");
  if (key == NULL)
    key = (unsigned char *)getpass("Enter passphrase: ");

  // 由于rc4是对称加密算法，这里运行rc4的功能是解密数据
  if (rc4(program, filesize - offset, key) == 1)
    return EXIT_FAILURE;

  // 消除用户输入密码，以防止泄露
  /* Overwrite key with random shit to hide its true contents. */
  for(; *key; key++)
    *key = characters[rand() % sizeof(characters) - 1];

  /* Some operating systems may not supply this function. This has only
   * been tested on modern Linux distributions (as of 2018). Alternatively,
   * you can modify this to utilize a temporary file or shm_open(). We use the
   * memfd_create() system call here to avoid writes to the disk.
   *
   * 翻译：一些操作系统可能没有提供这个函数。这个函数只在现代的Linux发行版（2018年时）上进行过测试。
   * 另外，你也可以修改这个函数，使用临时文件或者shm_open()来实现。
   * 我们在这里使用memfd_create()系统调用来避免对磁盘进行写操作。
   */
  
  // 创建一个与文件系统没有关联的文件对象，并返回该文件对象的文件描述符
  // 等于这个文件的操作都在内存（虚拟内存）里完成
  fd = memfd_create("asdf", 1);  // #define MFD_CLOEXEC     0x0001U
  if (fd == -1)
    return EXIT_FAILURE;

  /* Write decrypted program data to memory file descriptor */
  // 将解密的程序数据写入内存文件描述符
  if (write(fd, program, filesize - offset) != filesize - offset)
    return EXIT_FAILURE;

  /* Overwrite decrypted program with randomness before unmapping it.*/
  // 在解密程序之后，使用随机值覆盖程序数据，并取消映射
  for(i = 0; i < filesize - offset; i++, program++)
    *((char *)program) = rand() % 0xff;

  munmap(program, filesize);
  close(in);

  /* Attempt to execute decrypted ELF which is stored in memory fd. */
  // 尝试执行存储在内存文件描述符中的解密 ELF 文件
  fexecve(fd, argv, envp);
  close(fd);

  return EXIT_SUCCESS;
}

