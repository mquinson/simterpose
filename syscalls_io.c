#include "syscalls_io.h"
#include "run_trace.h"

int syscalls_in[MAX_PID];

void init_syscalls_in() {
  int i;
  for(i=0;i<MAX_PID;i++)
    syscalls_in[i]=0;
}

int in_syscall(int pid) {
  return syscalls_in[pid];
}

void set_in_syscall(int pid) {
  syscalls_in[pid]=1;
}

void set_out_syscall(int pid) {
  syscalls_in[pid]=0;
}


