#include "syscalls_io.h"
#include "run_trace.h"
#include "data_utils.h"

#include <stdlib.h>

int in_syscall(pid_t pid) {
  process_descriptor *proc = process_descriptor_get(pid);
  return proc->syscall_in;
}

void set_in_syscall(pid_t pid) {
  process_descriptor *proc = process_descriptor_get(pid);
  proc->syscall_in=1;
}

void set_out_syscall(pid_t pid) {
  process_descriptor *proc = process_descriptor_get(pid);
  proc->syscall_in=0;
}


