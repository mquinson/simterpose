/* sys_recvfrom -- Handlers recvfrom syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "ptrace_utils.h"
#include "syscall_data.h"
#include "process_descriptor.h"

void syscall_recvfrom(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void process_recvfrom_out_call(process_descriptor_t * proc);

void sys_translate_recvfrom_out(process_descriptor_t * proc, syscall_arg_u * sysarg);
