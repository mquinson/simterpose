#include "peek_data.h"


void ptrace_cpy(pid_t child, void * dst, void * src, size_t len, char *syscall) {   

  size_t i = 0;

  while (i < len / sizeof(long)) {
    long ret;
    errno = 0;
    ret = ptrace(PTRACE_PEEKDATA, child, src + i * sizeof(long), NULL);
    if (ret == -1 && errno != 0) {
      printf("ptrace peekdata in %s\n",syscall);
      exit(1);
    }
    ((long *)dst)[i] = ret;
    i++;
  }
}
