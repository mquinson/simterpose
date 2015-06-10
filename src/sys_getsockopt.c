/* sys_getsockopt -- Handles getsockopt syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_getsockopt.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles getsockopt syscall at the entrance at the exit */
void syscall_getsockopt(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_getsockopt_pre(reg, sysarg, proc);
  else
    syscall_getsockopt_post(reg, sysarg, proc);
      
}

/** @brief handles getsockopt syscall at the entrance if in full mediation */
void syscall_getsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
#ifndef address_translation
  get_args_getsockopt(proc, reg, sysarg);
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  pid_t pid = proc->pid;

  arg->ret = 0;
  if (arg->optname == SO_REUSEADDR) {
    arg->optlen = sizeof(int);
    arg->optval = xbt_malloc(sizeof(arg->optlen));
    *((int *) arg->optval) = socket_get_option(proc, arg->sockfd, SOCK_OPT_REUSEADDR);
  } else {
    XBT_WARN("Option non supported by Simterpose.");
    arg->optlen = 0;
    arg->optval = NULL;
  }

  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_getsockopt, arg->ret);

  if (arg->optname == SO_REUSEADDR) {
    ptrace_poke(pid, (void *) arg->dest, &(arg->optval), sizeof(arg->optlen));
    ptrace_poke(pid, (void *) arg->dest_optlen, &(arg->optlen), sizeof(socklen_t));
  }

  free(arg->optval);
  proc_outside(proc);
  if (strace_option)
    print_getsockopt_syscall(proc, sysarg);
#endif
}

/** @brief print getsockopt syscall at the exit */
void syscall_getsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  get_args_getsockopt(proc, reg, sysarg);
  if (strace_option)
    print_getsockopt_syscall(proc, sysarg);
}
