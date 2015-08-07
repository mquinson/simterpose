/* sys_create-- Handles create syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_creat.h"

#include "ptrace_utils.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles creat syscall at the entrance and the exit
    Create a file descriptor */
void syscall_creat(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    proc_inside(proc);
  else
    syscall_creat_post(reg, proc);

}

/** @brief handles creat syscall at the exit*/
void syscall_creat_post(reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
  char * pathname = (char *) xbt_malloc(200*sizeof(char));
  ptrace_cpy(proc->pid, pathname, (void *) reg->arg[0], 200*sizeof(char), "open");
    
  
  if ((int) reg->ret >= 0) {
    fd_descriptor_t *file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->refcount = 0;
    file_desc->fd = (int) reg->ret;
    file_desc->proc = proc;
    file_desc->type = FD_CLASSIC;
    file_desc->flags = O_CREAT|O_WRONLY|O_TRUNC;
    file_desc->mode = (int) reg->arg[1];
    file_desc->offset = 0;
    file_desc->lock = 0;
    process_descriptor_set_fd(proc, (int) reg->ret, file_desc);
    file_desc->refcount++;
  }

 if (strace_option)
   fprintf(stderr, "[%d] create(%s, %d) = %d \n", proc->pid, pathname, (int) reg->arg[1], (int) reg->ret);
}
