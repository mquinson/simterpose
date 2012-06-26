#include "ptrace_utils.h"
#include "sysdep.h"


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

void ptrace_resume_process(const pid_t pid)
{
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL)==-1) {
    perror("ptrace syscall");
    exit(1);
  }
}

void ptrace_detach_process(const pid_t pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1) {
    perror("ptrace detach");
    exit(1);
  }
}


void ptrace_get_register(const pid_t pid, syscall_arg* arg)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    perror("ptrace getregs");
    exit(1);
  }
  /* ---- test archi for registers ---- */
  #if defined(__x86_64) || defined(amd64)
  arg->reg_orig=regs.orig_rax;
  arg->ret=regs.rax;
  arg->arg1=regs.rdi;
  arg->arg2=regs.rsi;
  arg->arg3=regs.rdx;
  #elif defined(i386)
  arg->reg_orig=regs.orig_eax;
  arg->ret=regs.eax;
  arg->arg1=regs.ebx;
  arg->arg2=regs.ecx;
  arg->arg3=regs.edx;
  #endif
}

void ptrace_set_register(const pid_t pid)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    perror("ptrace getregs");
    exit(1);
  }
  //regs.rax=184;
  regs.orig_rax = 184;
  printf("eip = %lu\n", regs.rip);
  
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
    perror("ptrace getregs");
    exit(1);
  }

}

void ptrace_rewind_syscalls(const pid_t pid)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    perror("ptrace getregs");
    exit(1);
  }

  regs.rax = regs.orig_rax;
  regs.rip -= 2;
  printf("eip = %lu (%lu)\n", regs.rip, regs.rax);
  
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
    perror("ptrace getregs");
    exit(1);
  }
  
}

unsigned long ptrace_get_pid_fork(const pid_t pid)
{
  unsigned long new_pid;
  if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid)==-1) {
    perror("ptrace geteventmsg");
    exit(1);
  }
  return new_pid;
}
