/* sys_setsockopt -- Handles setsockopt syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_setsockopt.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles setsockopt syscall at the entrance at the exit */
void syscall_setsockopt(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_setsockopt_pre(reg, sysarg, proc);
  else
    syscall_setsockopt_post(reg, sysarg, proc);

}

/** @brief handles setsockopt syscall at the entrance if in full mediation */
void syscall_setsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
#ifndef address_translation
  get_args_setsockopt(proc, reg, sysarg);
  setsockopt_arg_t arg = &(sysarg->setsockopt);
  pid_t pid = proc->pid;
  //TODO really handles setsockopt that currently raise a warning
  arg->ret = 0;

  if (arg->optname == SO_REUSEADDR)
    socket_set_option(proc, arg->sockfd, SOCK_OPT_REUSEADDR, *((int *) arg->optval));
  else
    XBT_WARN("Option non supported by Simterpose.");

  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_setsockopt, arg->ret);

  proc_outside(proc);
  if (strace_option)
    print_setsockopt_syscall(proc, sysarg);
  free(sysarg->setsockopt.optval);
#endif
}

/** @brief print setsockopt syscall at the exit */
void syscall_setsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  get_args_setsockopt(proc, reg, sysarg);
  if (strace_option)
    print_setsockopt_syscall(proc, sysarg);
}
