#ifndef __SYSCALLS_IO_H 
#define __SYSCALLS_IO_H

#include <stdlib.h> //for pid_t typedef

int in_syscall(pid_t pid);

void set_in_syscall(pid_t pid);

void set_out_syscall(pid_t pid);

#endif
