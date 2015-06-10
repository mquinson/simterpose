/* sys_open -- Handles open syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_open.h"

#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles open syscall at the entrance and the exit
    Open a new file descriptor */
void syscall_open(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
  } else {
    proc_outside(proc);

    open_arg_t arg = &(sysarg->open);
    arg->ret = reg->ret;
    arg->ptr_filename = reg->arg[0];
    arg->flags = reg->arg[1]; // TODO arg[1] value is always 0, so we don't print actual flags for now

    if (arg->ret >= 0) {
      fd_descriptor_t *file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
      file_desc->refcount = 0;
      file_desc->fd = arg->ret;
      file_desc->proc = proc;
      file_desc->type = FD_CLASSIC;
      proc->fd_list[(int) reg->ret] = file_desc;
      file_desc->refcount++;
    }
    // TODO handle flags
    if (strace_option)
      print_open_syscall(proc, sysarg);
  
    printf("An open syscall was made for the fd %d via reg %lu\n", arg->ret, reg->ret);
  }
}
