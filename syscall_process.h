#ifndef INCLUDED_SYSCALL_PROCESS
#define INCLUDED_SYSCALL_PROCESS

#include <sys/types.h>          //for pid_t
#include "ptrace_utils.h"
#include "syscall_data.h"
#include "process_descriptor.h"

#define PROCESS_DEAD            0
#define PROCESS_GROUP_DEAD      1
#define PROCESS_IDLE_STATE      2
#define PROCESS_TASK_FOUND      3
#define PROCESS_NO_TASK_FOUND   4
#define PROCESS_ON_MEDIATION    5
#define PROCESS_ON_COMPUTATION  6
#define PROCESS_CONTINUE        7

#define RECV_CLOSE              10

int process_handle(process_descriptor_t *proc, int status);

int process_handle_active(process_descriptor_t *proc);

int process_handle_idle(process_descriptor_t *proc);

int process_handle_mediate(process_descriptor_t *proc);

#endif
