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


  /* Seed RNG */
  srand(time(NULL));

  /* Calculate size of the stub + encrypted ELF */
  filesize = get_file_size(argv[0]);

  /* Calculate size of the stub */
  offset = get_elf_size(argv[0]);
  if (offset == -1)
    return EXIT_FAILURE;

  /* Open stub + encrypted ELF for reading, then mmap() it */
  in = open(argv[0], O_RDONLY);
  if (in == -1)
    return EXIT_FAILURE;

  program = mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, in, 0);
  if (program == MAP_FAILED)
    return EXIT_FAILURE;

  /* Skip the stub. The encrypted data lies right after the stub. */
  program += offset;

  /* Attempt to decrypt the ELF using the key supplied by the user */
  key = (unsigned char *)getenv("ELFCRYPT");
  if (key == NULL)
    key = (unsigned char *)getpass("Enter passphrase: ");

  if (rc4(program, filesize - offset, key) == 1)
    return EXIT_FAILURE;

  /* Overwrite key with random shit to hide its true contents. */
  for(; *key; key++)
    *key = characters[rand() % sizeof(characters) - 1];

  /* Some operating systems may not supply this function. This has only
   * been tested on modern Linux distributions (as of 2018). Alternatively,
   * you can modify this to utilize a temporary file or shm_open(). We use the
   * memfd_create() system call here to avoid writes to the disk.
   */
  fd = memfd_create("asdf", 1);
  if (fd == -1)
    return EXIT_FAILURE;

  /* Write decrypted program data to memory file descriptor */
  if (write(fd, program, filesize - offset) != filesize - offset)
    return EXIT_FAILURE;

  /* Overwrite decrypted program with randomness before unmapping it.*/
  for(i = 0; i < filesize - offset; i++, program++)
    *((char *)program) = rand() % 0xff;

  munmap(program, filesize);
  close(in);

  /* Attempt to execute decrypted ELF which is stored in memory fd. */
  fexecve(fd, argv, envp);
  close(fd);

  return EXIT_SUCCESS;
}

