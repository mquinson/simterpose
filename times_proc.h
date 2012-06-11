#ifndef __TIME_PROC_H_ 
#define __TIME_PROC_H_

#include "sysdep.h"

void insert_walltime_procs(pid_t pid);

void update_walltime_procs(pid_t pid, long long int time_elapsed);

long long int get_last_walltime(pid_t pid);

int update_cputime_procs(pid_t pid, long long int cputime_elapsed);

long long int get_last_cputime(pid_t pid);

#endif
