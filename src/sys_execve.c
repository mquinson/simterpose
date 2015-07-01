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
  arg->ret = (int) reg->ret;
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

    xbt_dict_cursor_t cursor = NULL;
    char *key;
    fd_descriptor_t* file_desc;
    xbt_dict_foreach(proc->fd_map, cursor, key, file_desc)
      if (file_desc->flags == FD_CLOEXEC)
        XBT_WARN("FD_CLOEXEC not handled");

    XBT_DEBUG("execve retour");
  }
}
