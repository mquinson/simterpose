/* sys_tuxcall -- Handles tuxcall syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <simgrid/msg.h>

#include "simterpose.h"
#include "print_syscall.h"
#include "sys_tuxcall.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

void syscall_tuxcall(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    proc_inside(proc); /* syscall_tuxcall_pre */
  else
    syscall_tuxcall_post(reg, proc);
  
}

void syscall_tuxcall_post(reg_s * reg, process_descriptor_t * proc){

  proc_outside(proc);
  XBT_DEBUG("tuxcall_post");
  
  double clock = MSG_get_clock();
  ptrace_poke(proc->pid, (void *) reg->arg[1], &clock, sizeof(double));

  if (strace_option)
    print_tuxcall_syscall(reg, proc);
}
