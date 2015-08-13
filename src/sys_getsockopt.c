/* sys_getsockopt -- Handles getsockopt syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_getsockopt.h"

#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles getsockopt syscall at the entrance at the exit */
void syscall_getsockopt(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_getsockopt_pre(reg, proc);
  else
    syscall_getsockopt_post(reg, proc);

}

/** @brief handles getsockopt syscall at the entrance if in full mediation */
void syscall_getsockopt_pre(reg_s * reg, process_descriptor_t * proc)
{
  printf("in get\n");
  proc_inside(proc);
#ifndef address_translation
  pid_t pid = proc->pid;
  void * optval = xbt_malloc0(sizeof(int));
  reg->ret = 0;

  ptrace_cpy(pid, optval, (void *) reg->arg[3], sizeof(int), "getsockopt");
  
  if (reg->arg[2] == SO_REUSEADDR) {
    *((int *)optval) = socket_get_option(proc, reg->arg[0], SOCK_OPT_REUSEADDR);
  } else {
    XBT_WARN("Option non supported by Simterpose.");
  }

  /* if (arg->reg->arg[2] == SO_REUSEADDR) { */
  /*   ptrace_poke(pid, (void *) arg->dest, &(arg->optval), sizeof(arg->optlen)); */
  /*   ptrace_poke(pid, (void *) arg->dest_optlen, &(arg->optlen), sizeof(socklen_t)); */
  /* } */
  /* TODO */

  if (reg->arg[2] == SO_REUSEADDR) {
    /* ptrace_poke(pid, (void *) arg->dest, &(arg->optval), sizeof(arg->optlen)); */
    /* ptrace_poke(pid, (void *) arg->dest_optlen, &(arg->optlen), sizeof(socklen_t)); */
    /* TODO */
  }

  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_getsockopt, (int) reg->ret);
  proc_outside(proc);
  if (strace_option)
    print_getsockopt_syscall(reg, proc);
  printf("out get\n");
#endif
}

/** @brief print getsockopt syscall at the exit */
void syscall_getsockopt_post(reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
#ifndef address_translation
  void * optval = xbt_new0(char, (socklen_t) reg->arg[4]);
  ptrace_cpy(proc->pid, optval, (void *) reg->arg[3], (socklen_t) reg->arg[4], "setsockopt");
#endif

  if (strace_option)
    print_getsockopt_syscall(reg, proc);
}
