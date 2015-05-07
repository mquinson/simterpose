/* sys_network -- Handles every network-related syscalls                       */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "syscall_data.h"

void syscall_socket(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_accept(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg);
void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_listen(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg);
void syscall_getpeername_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_shutdown_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_shutdown_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_recvfrom_out_call(process_descriptor_t * proc);
int syscall_sendmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

void syscall_getsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_getsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_setsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_setsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
