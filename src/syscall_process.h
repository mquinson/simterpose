/* syscall_process -- Handles every syscall at the entrance/exit. */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef SYSCALL_PROCESS_H
#define SYSCALL_PROCESS_H

/* Memory-related */
#include "sys_memory.h"
/* Network-related */
#include "sys_network.h"
/* Process-related */
#include "sys_process.h"

#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "sockets.h"
/* #include "sys_process.h" */


enum { PROCESS_CONTINUE = 0, PROCESS_DEAD, PROCESS_GROUP_DEAD, PROCESS_TASK_FOUND };
extern const char *state_names[4];

#define RECV_CLOSE              10

int process_handle(process_descriptor_t * proc);
int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc);
void process_close_call(process_descriptor_t * proc, int fd);
int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg);

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
int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_accept(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg);
int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_sendmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_recvfrom_out_call(process_descriptor_t * proc);
void syscall_shutdown_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_shutdown_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_listen(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg);
void syscall_getpeername_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_getsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_getsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_setsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_setsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
#endif
