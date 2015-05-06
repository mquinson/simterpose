/* syscall_process -- Handles every syscall at the entrance/exit. */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef SYSCALL_PROCESS_H
#define SYSCALL_PROCESS_H

#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "sockets.h"

enum { PROCESS_CONTINUE = 0, PROCESS_DEAD, PROCESS_GROUP_DEAD, PROCESS_TASK_FOUND };
extern const char *state_names[4];

#define RECV_CLOSE              10

int process_handle(process_descriptor_t * proc);
int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc);
void process_close_call(process_descriptor_t * proc, int fd);

/* memory-related */
void syscall_brk(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_read(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_read_out_call(process_descriptor_t * proc);
int syscall_write(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_open(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_close(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_poll_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_poll_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_pipe_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_select_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_dup2_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

/* process-related */
void syscall_execve(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_clone(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

/* Network-related */
void syscall_socket(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

#endif
