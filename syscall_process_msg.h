#ifndef SYSCALL_PROCESS_MSG_H
#define SYSCALL_PROCESS_MSG_H

#include "process_descriptor_msg.h"
#include "ptrace_utils_msg.h"

enum { PROCESS_CONTINUE = 0, PROCESS_DEAD, PROCESS_GROUP_DEAD, PROCESS_TASK_FOUND };
extern const char *state_names[4];

#define RECV_CLOSE              10

int process_handle_msg(process_descriptor_t * proc, int status);

#endif
