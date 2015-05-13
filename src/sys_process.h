/* sys_mem -- Handles every memory-syscall. */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

/* #ifndef SYSCALL_PROCESS_H */
/* #define SYSCALL_PROCESS_H */

#include "process_descriptor.h"
#include "syscall_data.h"
#include "ptrace_utils.h"
#include "syscall_process.h" /* Just to have a definition of PROCESS_DEAD */

void syscall_clone(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
void syscall_execve(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
int syscall_exit(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);

/* #endif */
