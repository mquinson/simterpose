/* sys_brk -- Handles of brk syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_brk.h"

#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles brk syscall at the entrance and the exit */
void syscall_brk(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc) {
  if (proc_entering(proc)) {
    proc_inside(proc);
  } else {
    proc_outside(proc);

    if (!strace_option)
      return;

    if (reg->arg[0])
      stprintf(proc,"brk(%#lx)",reg->arg[0]);
    else
      stprintf(proc,"brk(0)");
    stprintf_tabto(proc);
    stprintf(proc,"= %#lx",reg->ret);
    stprintf_eol(proc);
  }
}
