/* sys_exit -- Handlers exit syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "ptrace_utils.h"
#include "syscall_data.h"
#include "process_descriptor.h"

int syscall_exit(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc);
