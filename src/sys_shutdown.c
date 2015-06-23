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
void syscall_shutdown(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_shutdown_pre(reg, sysarg, proc);
  else
    syscall_shutdown_post(reg, sysarg, proc);

}

/** @brief handles shutdown syscall at the entrace if in full mediation
 *
 * In case of full mediation, we neutralize the real syscall and don't
 * go to syscall_shutdown_post afterwards.
 */
void syscall_shutdown_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
#ifndef address_translation
  XBT_DEBUG(" shutdown_pre");
  shutdown_arg_t arg = &(sysarg->shutdown);
  arg->fd = reg->arg[0];
  arg->how = reg->arg[1];
  arg->ret = reg->ret;

  ptrace_neutralize_syscall(proc->pid);
  arg->ret = 0;
  ptrace_restore_syscall(proc->pid, SYS_shutdown, arg->ret);
  proc_outside(proc);
  if (strace_option)
    print_shutdown_syscall(proc, sysarg);
#endif
}

/** @brief handles shutdown syscall at the exit in case of address translation */
void syscall_shutdown_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  XBT_DEBUG(" shutdown_post");
  proc_outside(proc);
  shutdown_arg_t arg = &(sysarg->shutdown);
  arg->fd = reg->arg[0];
  arg->how = reg->arg[1];
  arg->ret = reg->ret;

  struct infos_socket *is = get_infos_socket(proc, arg->fd);
  if (is == NULL) {
    arg->ret = -EBADF;
    return;
  }
  comm_shutdown(is);

  if (strace_option)
    print_shutdown_syscall(proc, sysarg);
}
