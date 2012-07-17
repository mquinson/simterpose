#ifndef INCLUDED_SYSCALL_PROCESS
#define INCLUDED_SYSCALL_PROCESS

#include <sys/types.h> //for pid_t
#include "ptrace_utils.h"
#include "syscall_data.h"

#define PROCESS_DEAD            0
#define PROCESS_GROUP_DEAD      1
#define PROCESS_IDLE_STATE      2
#define PROCESS_TASK_FOUND      3
#define PROCESS_NO_TASK_FOUND   4
#define PROCESS_ON_MEDIATION    5

int process_send_call(pid_t pid, syscall_arg_u* sysarg);

int process_recv_call(pid_t pid, syscall_arg_u* sysarg);

int process_fork_call(pid_t pid);

int process_handle(pid_t pid, int status);

int process_handle_active(pid_t pid);

int process_handle_idle(pid_t pid);

int process_clone_call(pid_t pid, reg_s *arg);

#endif