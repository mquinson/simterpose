#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net.h>
#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <linux/cgroupstats.h>
#include <linux/netlink.h>

typedef struct {
  unsigned long reg_orig;
  unsigned long ret;
  unsigned long arg1;
  unsigned long arg2;
  unsigned long arg3;
} syscall_arg;

void ptrace_resume_process(const pid_t pid)
{
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
    perror("ptrace syscall");
    exit(1);
  }
}

void ptrace_get_register(const pid_t pid, syscall_arg * arg)
{
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
    perror("ptrace getregs");
    exit(1);
  }
  /* ---- test archi for registers ---- */
#if defined(__x86_64) || defined(amd64)
  arg->reg_orig = regs.orig_rax;
  arg->ret = regs.rax;
  arg->arg1 = regs.rdi;
  arg->arg2 = regs.rsi;
  arg->arg3 = regs.rdx;
#elif defined(i386)
  arg->reg_orig = regs.orig_eax;
  arg->ret = regs.eax;
  arg->arg1 = regs.ebx;
  arg->arg2 = regs.ecx;
  arg->arg3 = regs.edx;
#endif
}


void main()
{
  int status;
  syscall_arg arg;
  if (fork() == 0) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      perror("ptrace traceme");
      exit(1);
    }
    if (execl("./server", "./server", NULL) == -1) {
      perror("execl");
      exit(1);
    }

  } else {
    int pid = waitpid(-1, &status, 0);

    //We set option for trace all of this son
    if (ptrace
        (PTRACE_SETOPTIONS, pid, NULL,
         PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE) == -1) {
      perror("Error setoptions");
      exit(1);
    }

    ptrace_resume_process(pid);

    while ((pid = waitpid(-1, &status, __WALL)) > 0) {
      ptrace_get_register(pid, &arg);
      printf("Syscall %d %lu %lu\n", pid, arg.reg_orig, arg.ret);
      ptrace_resume_process(pid);
    }
  }
}
