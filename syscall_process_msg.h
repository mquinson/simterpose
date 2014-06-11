#ifndef SYSCALL_PROCESS_MSG_H
#define SYSCALL_PROCESS_MSG_H

#include "process_descriptor_msg.h"
#include "ptrace_utils_msg.h"

void process_handle_msg(process_descriptor_t * proc);

void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

#endif
