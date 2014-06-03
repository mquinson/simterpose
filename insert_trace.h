#ifndef __INSERT_TRACE_H_
#define __INSERT_TRACE_H_

#include <sys/types.h>
#include "process_descriptor.h"

extern int nb_procs;

void insert_trace_comm(pid_t pid, int sockfd, char *syscall, int res);

void insert_trace_fork_exit(pid_t pid, char *syscall, int res);

void insert_init_trace(pid_t pid);

int compute_computation_time(process_descriptor_t *proc);

#endif
