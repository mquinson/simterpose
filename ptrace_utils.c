#include "ptrace_utils.h"
#include "sysdep.h"
#include "xbt.h"


void ptrace_cpy(pid_t child, void * dst, void * src, size_t len, char *syscall) {   

  int i = 0;
  long size_copy =0;

  errno = 0;
  long ret;
  while (size_copy < len) {
    ret = ptrace(PTRACE_PEEKDATA, child, src + i * sizeof(long), NULL);
    if (ret == -1 && errno != 0) {
      printf("%s : ptrace peekdata in %s\n",strerror(errno), syscall);
      THROW_IMPOSSIBLE;
    }
    ((long *)dst)[i] = ret;
    size_copy += sizeof(long);
    i++;
  }
}

void ptrace_poke(pid_t pid, void* dst, void* src, size_t len)
{
  size_t size_copy =0;
  long ret;
  errno = 0;
  while (size_copy < len) {
    ret = ptrace(PTRACE_POKEDATA, pid, dst +size_copy, *((long*)(src + size_copy)));
    if (ret == -1 && errno != 0) {
      perror("ptrace pokedata");
      THROW_IMPOSSIBLE;
    }
    size_copy += sizeof(long);
  }
}

void ptrace_resume_process(const pid_t pid)
{
//   printf("Resume process %d\n", pid);
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL)==-1) {
    fprintf(stderr, " [%d] ptrace syscall %s\n", pid, strerror(errno));
    THROW_IMPOSSIBLE;
    xbt_die("Impossible to continue\n");
  }
}

void ptrace_detach_process(const pid_t pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1) {
    perror("ptrace detach");
    xbt_die("Impossible to continue\n");
  }
}


int ptrace_record_socket(pid_t pid)
{
  struct user_regs_struct save_reg, reg;
  if (ptrace(PTRACE_GETREGS, pid,NULL, &save_reg) == -1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &reg) == -1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  
  reg.orig_rax = SYS_socket;
  reg.rdi = AF_INET;
  reg.rsi = SOCK_STREAM;
  reg.rdx = 0;
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &reg)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  ptrace_resume_process(pid);
  
  int status;
  waitpid(pid, &status, 0);
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &reg) == -1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  
  int res = (int)reg.rax;
 
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &save_reg)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  ptrace_rewind_syscalls(pid);
  ptrace_resume_process(pid);
  
  waitpid(pid, &status, 0);
  
  return res;
}


void ptrace_get_register(const pid_t pid, reg_s* arg)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs) == -1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  /* ---- test archi for registers ---- */
  arg->reg_orig=regs.orig_rax;
  arg->ret=regs.rax;
  arg->arg1=regs.rdi;
  arg->arg2=regs.rsi;
  arg->arg3=regs.rdx;
  arg->arg4=regs.r10;
  arg->arg5=regs.r8;
  arg->arg6=regs.r9;
}

void ptrace_set_register(const pid_t pid)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  //regs.rax=184;
  regs.orig_rax = 184;  
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }

}


void ptrace_neutralize_syscall(const pid_t pid)
{
  struct user_regs_struct regs;
  int status;
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  regs.orig_rax = 184;
  if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  ptrace_resume_process(pid);
  waitpid(pid, &status, 0);
}

void ptrace_restore_syscall(pid_t pid, unsigned long syscall, unsigned long result)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  
  regs.orig_rax = syscall;
  regs.rax = result;
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
}

void ptrace_rewind_syscalls(const pid_t pid)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }

  regs.rax = regs.orig_rax;
  regs.rip -= 2;  
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  
}

unsigned long ptrace_get_pid_fork(const pid_t pid)
{
  unsigned long new_pid;
  if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid)==-1) {
    perror("ptrace geteventmsg");
    xbt_die("Impossible to continue\n");
  }
  return new_pid;
}

int ptrace_find_free_binding_port(const pid_t pid)
{
  struct user_regs_struct save_reg;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &save_reg)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  
  struct user_regs_struct reg;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &reg)==-1) {
    fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
    xbt_die("Impossible to continue\n");
  }
  struct sockaddr_in in;
  struct sockaddr_in temp;
  ptrace_cpy(pid, &in, (void*)reg.rsi, reg.rdx, "");
  temp=in;
  
  unsigned short port = 0;
  --port;
  int status;
  
  while(1)
  {
    temp.sin_port = htons(port);
    temp.sin_addr.s_addr = inet_addr("127.0.0.1");
    ptrace_poke(pid, (void*)reg.rsi, &temp, reg.rdx);
    ptrace_resume_process(pid);
    waitpid(pid, &status, 0);
    if (ptrace(PTRACE_GETREGS, pid,NULL, &reg)==-1) {
      fprintf(stderr, " [%d] ptrace getregs %s\n", pid, strerror(errno));
      xbt_die("Impossible to continue\n");
    }
    if(reg.rax == 0)
      break;
    
    --port;
    ptrace_rewind_syscalls(pid);
    ptrace_resume_process(pid);
    waitpid(pid, &status, 0);
  }
  ptrace_poke(pid, (void*)reg.rsi, &in, reg.rdx);
  
  return port;
}

