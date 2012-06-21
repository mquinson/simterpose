#ifndef INCLUDED_SYSCALL_PROCESS
#define INCLUDED_SYSCALL_PROCESS

#include <sys/types.h> //for pid_t

#include "simdag/simdag.h"

#define PROCESS_DEAD 0
#define PROCESS_IDLE_STATE 1
#define PROCESS_TASK_FOUND 2

int process_send_call(pid_t pid, int sockfd, int ret);

int process_recv_call(pid_t pid, int sockfd, int ret);

int process_fork_call(pid_t pid);

int process_handle(pid_t pid, SD_task_t task);

#endif