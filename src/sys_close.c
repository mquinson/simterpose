/* sys_close -- Handles close syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_close.h"

#include "print_syscall.h"
#include "simterpose.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles close syscall at the entrance and the exit
    Close a file descriptor */
void syscall_close(reg_s * reg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
  } else {
    if (reg->ret == 0){
      proc_outside(proc);
      int fd = reg->arg[0];
      process_close_call(proc, fd);
      if(strace_option) {
	stprintf(proc,"close(%d)",fd);
	stprintf_tabto(proc);
	stprintf(proc,"= %lu",reg->ret);
	stprintf_eol(proc);
      }
    }
    
    if (strace_option)
      print_close_syscall(reg, proc);
  }
}
