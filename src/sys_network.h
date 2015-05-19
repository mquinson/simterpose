/* sys_network -- Handlers every network-related syscalls                       */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "syscall_data.h"

/* enum { PROCESS_CONTINUE = 0, PROCESS_DEAD, PROCESS_GROUP_DEAD, PROCESS_TASK_FOUND }; */

void syscall_socket(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_connect(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg);

void syscall_bind(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_listen(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg);

void syscall_accept(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg);

int syscall_sendto(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_recvfrom(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_recvfrom_out_call(process_descriptor_t * proc);

int syscall_sendmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_recvmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_shutdown(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_shutdown_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_shutdown_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_getpeername(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_getpeername_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_getsockopt(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_getsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_getsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_setsockopt(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_setsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_setsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
