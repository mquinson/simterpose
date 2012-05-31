#ifndef __INSERT_TRACE_H_ 
#define __INSERT_TRACE_H_

#include "sysdep.h"
#include "sockets.h"
#include "syscalls_io.h"
#include "calc_times_proc.h"
#include "times_proc.h"
#include "run_trace.h"

extern struct time_process all_procs[MAX_PROCS]; 
extern int nb_procs;
extern process_descriptor process_desc[MAX_PID];

void insert_trace_comm(int simgrid, FILE *trace, pid_t pid, int sockfd, char *syscall, char* type, ...);

void insert_trace_fork_exit(int simgrid, FILE *trace, pid_t pid, char *syscall, int res);

#endif
