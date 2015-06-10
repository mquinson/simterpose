/* sys_listen -- Handles listen syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_listen.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles listen syscall at the entrance and the exit */
void syscall_listen(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {

    proc_inside(proc);
#ifndef address_translation
    get_args_listen(proc, reg, sysarg);
    process_listen_call(proc, sysarg);
    if (strace_option)
      print_listen_syscall(proc, sysarg);
#endif
  } else {
    proc_outside(proc);
#ifdef address_translation
    get_args_listen(proc, reg, sysarg);
    process_listen_call(proc, sysarg);
    if (strace_option)
      print_listen_syscall(proc, sysarg);
#else
    THROW_IMPOSSIBLE;
#endif
  }
}

/** @brief helper function to handle listen syscall
 *
 * We create a new communication and put it in a listening state.
 * In case of full mediation, we neutralize the real syscall and don't
 * go to syscall_listen_post afterwards.
 *
 */
void process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  listen_arg_t arg = &(sysarg->listen);
  struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
  comm_t comm = comm_new(is);
  comm_set_listen(comm);

#ifndef address_translation
  pid_t pid = proc->pid;
  arg->ret = 0;
  ptrace_neutralize_syscall(pid);
  arg = &(sysarg->listen);
  ptrace_restore_syscall(pid, SYS_listen, arg->ret);
  proc_outside(proc);
#endif
}
