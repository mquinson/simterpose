/* sys_exit -- Handles exit syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_exit.h"

#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);


/** @brief handles exit syscall at the entrance and the exit */
int syscall_exit(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
    ptrace_detach_process(pid);
    return PROCESS_DEAD;
  } else {
    THROW_IMPOSSIBLE;
  }
}
