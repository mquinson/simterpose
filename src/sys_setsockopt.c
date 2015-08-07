/* sys_setsockopt -- Handles setsockopt syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_setsockopt.h"

#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles setsockopt syscall at the entrance at the exit */
void syscall_setsockopt(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_setsockopt_pre(reg, proc);
  else
    syscall_setsockopt_post(reg, proc);

}

/** @brief handles setsockopt syscall at the entrance if in full mediation */
/* We consider that optval is uselly an int */
void syscall_setsockopt_pre(reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);
#ifndef address_translation
  pid_t pid = proc->pid;
  if ( (int) reg->arg[2] == SO_REUSEADDR){
    int * optval = xbt_malloc(sizeof(int));
    ptrace_cpy(proc->pid, optval, (void *) reg->arg[3], sizeof(int), "setsockopt");
    socket_set_option(proc, (int) reg->arg[0], SOCK_OPT_REUSEADDR, *optval);
    reg->ret = 0;
  }
  else{
    XBT_WARN("Option non supported by Simterpose.");
    reg->ret = -1;
  }
  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_setsockopt, (int) reg->ret);

  proc_outside(proc);
  if (strace_option)
    print_setsockopt_syscall(reg, proc);
#endif
}

/** @brief print setsockopt syscall at the exit */
void syscall_setsockopt_post(reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
  if (strace_option)
    print_setsockopt_syscall(reg, proc);
}
