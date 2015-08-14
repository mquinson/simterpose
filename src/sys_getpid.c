/* sys_getpid -- Handles getpid syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */
/* Author Louisa Bessad */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_getpid.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

void syscall_getpid(reg_s * reg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) 
    {
      proc_inside(proc);
      XBT_DEBUG("getpid pre");
    }
  else{
    proc_outside(proc);
    XBT_DEBUG("getpid poist");
    sys_getpid_post(reg, proc);
  }

}

void sys_getpid_post(reg_s * reg, process_descriptor_t * proc)
{
  if ((pid_t) reg->ret < 0)
    return;

  if (strace_option)
    fprintf(stderr, "[%d] getpid() = %d \n", proc->pid, (pid_t) reg->ret);

}
