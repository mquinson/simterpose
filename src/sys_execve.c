/* sys_execve -- Handles execve syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

/* #include <xbt.h> */

#include "sys_execve.h"

#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles execve syscall at the entrance and the exit */
void syscall_execve(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc) {
  execve_arg_t arg = &(sysarg->execve);
  arg->ret = reg->ret;
  arg->ptr_filename = reg->arg[0];
  arg->ptr_argv = reg->arg[1];

  if (proc_event_exec(proc)) {
    XBT_DEBUG("Ignore an exec event");

  } else if (proc_entering(proc)) {
    proc_inside(proc);
    if (strace_option)
      print_execve_syscall_pre(proc, sysarg);

  } else {
    proc_outside(proc);
    if (strace_option)
      print_execve_syscall_post(proc, sysarg);

    int i;
    for (i = 0; i < MAX_FD; ++i) {
      if (process_descriptor_get_fd(proc, i) != NULL) {
	// XBT_WARN("fd n° %d; process_descriptor_get_fd(proc, i)->flags = %d\n ", i, process_descriptor_get_fd(proc, i)->flags);
	if (process_descriptor_get_fd(proc, i)->flags == FD_CLOEXEC)
	  XBT_WARN("FD_CLOEXEC not handled");
	//process_close_call(proc, i);
      }
    }
    XBT_DEBUG("execve retour");
  }
}
