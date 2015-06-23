/* sys_create-- Handles create syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_create.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles creat syscall at the entrance and the exit
    Create a file descriptor */
void syscall_creat(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    proc_inside(proc);
  else
    syscall_creat_post(reg, sysarg, proc);

}

/** @brief handles creat syscall at the exit*/
void syscall_creat_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  if ((int) reg->ret >= 0) {
    fd_descriptor_t *file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->refcount = 0;
    file_desc->fd = (int) reg->ret;
    file_desc->proc = proc;
    file_desc->type = FD_CLASSIC;
    process_descriptor_set_fd(proc, (int) reg->ret, file_desc);
    file_desc->refcount++;
  }
}
