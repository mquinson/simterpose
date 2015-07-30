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
void syscall_open(reg_s * reg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
  } else {
    proc_outside(proc);

    if (((int) reg->ret) >= 0) {
      fd_descriptor_t *file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
      file_desc->refcount = 0;
      file_desc->fd = (int) reg->ret;
      file_desc->proc = proc;
      file_desc->type = FD_CLASSIC;
      file_desc->flags = (int) reg->arg[1];
      file_desc->mode = reg->arg[2];
      process_descriptor_set_fd(proc, reg->ret, file_desc);
      file_desc->refcount++;
    }
    // TODO handle flags
    if (strace_option)
      print_open_syscall(reg, proc);

  /*   XBT_DEBUG("An open syscall was made for the fd %d via reg %lu\n Value of flags %lu \n", arg->ret, reg->ret, arg->flags); */
  }
}
