#ifndef __PEEK_DATA_H 
#define __PEEK_DATA_H

#include "sysdep.h"

typedef struct{
  unsigned long reg_orig;
  unsigned long ret;
  unsigned long arg1;
  unsigned long arg2;
  unsigned long arg3;
}syscall_arg;


void ptrace_cpy(pid_t child, void * dst, void * src, size_t len, char *syscall);

void ptrace_resume_process(const pid_t pid);

void ptrace_get_register(const pid_t pid, syscall_arg* arg);

unsigned long ptrace_get_pid_fork(const pid_t pid);


#endif

