/* sys_shutdown -- Handles shutdown syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_shutdown.h"

#include "args_trace.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles shutdown syscall at the entrance at the exit */
void syscall_shutdown(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_shutdown_pre(reg, proc);
  else
    syscall_shutdown_post(reg, proc);

}

/** @brief handles shutdown syscall at the entrace if in full mediation
 *
 * In case of full mediation, we neutralize the real syscall and don't
 * go to syscall_shutdown_post afterwards.
 */
void syscall_shutdown_pre(reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);
#ifndef address_translation
  XBT_DEBUG(" shutdown_pre");

  ptrace_neutralize_syscall(proc->pid);
  reg->ret = 0;
  ptrace_restore_syscall(proc->pid, SYS_shutdown, (int) reg->ret);
  proc_outside(proc);
  if (strace_option)
    print_shutdown_syscall(reg, proc);
#endif
}

/** @brief handles shutdown syscall at the exit in case of address translation */
void syscall_shutdown_post(reg_s * reg, process_descriptor_t * proc)
{
  XBT_DEBUG(" shutdown_post");
  proc_outside(proc);

  struct infos_socket *is = get_infos_socket(proc, (int) reg->arg[0]);
  if (is == NULL) {
    reg->ret = -EBADF;
    return;
  }
  comm_shutdown(is);

  if (strace_option)
    print_shutdown_syscall(reg, proc);
}
