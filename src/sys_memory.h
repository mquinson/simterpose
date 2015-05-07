/* sys_mem -- handles of all memory-related syscalls                        */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "ptrace_utils.h"
#include "syscall_data.h"
#include "process_descriptor.h"

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
void syscall_fcntl(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_fcntl_call(process_descriptor_t * proc, syscall_arg_u * sysarg);
void syscall_creat_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
