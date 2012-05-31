#ifndef __SYSCALLS_IO_H 
#define __SYSCALLS_IO_H

#include "sysdep.h"

#define MAX_PID 32768  


int in_syscall(int pid);

void set_in_syscall(int pid);

void set_out_syscall(int pid);

void init_syscalls_in();

#endif
