#ifndef __TIME_PROC_H_ 
#define __TIME_PROC_H_

#include "sysdep.h"

int update_cputime_procs(pid_t pid, long long int cputime_elapsed);

long long int get_last_cputime(pid_t pid);

int in_syscall(pid_t pid);

void set_in_syscall(pid_t pid);

void set_out_syscall(pid_t pid);

#endif
