#ifndef __INSERT_TRACE_H_ 
#define __INSERT_TRACE_H_

#define TYPE_OUT 1
#define TYPE_IN 0

#include "sysdep.h"
#include "sockets.h"
#include "syscalls_io.h"
#include "calc_times_proc.h"
#include "times_proc.h"
#include "run_trace.h"




extern struct time_process all_procs[MAX_PROCS]; 
extern int nb_procs;
extern process_descriptor process_desc[MAX_PID];

void insert_trace_comm(pid_t pid, int sockfd, char *syscall, int type, int res);

void insert_trace_fork_exit(pid_t pid, char *syscall, int res);

void insert_init_trace(pid_t pid);

#endif
