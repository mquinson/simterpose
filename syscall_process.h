#ifndef INCLUDED_SYSCALL_PROCESS
#define INCLUDED_SYSCALL_PROCESS

#include <sys/types.h>          //for pid_t
#include "ptrace_utils.h"
#include "syscall_data.h"

#define PROCESS_DEAD            0
#define PROCESS_GROUP_DEAD      1
#define PROCESS_IDLE_STATE      2
#define PROCESS_TASK_FOUND      3
#define PROCESS_NO_TASK_FOUND   4
#define PROCESS_ON_MEDIATION    5
#define PROCESS_ON_COMPUTATION  6
#define PROCESS_CONTINUE        7

#define RECV_CLOSE              10

int process_handle(pid_t pid, int status);

int process_handle_active(pid_t pid);

int process_handle_idle(pid_t pid);

int process_handle_mediate(pid_t pid);

#endif
