/* sys_getpeername -- Handles getpeername syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_getpeername.h"

#include "args_trace.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles getpeername syscall at the entrance at the exit */
void syscall_getpeername(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_getpeername_pre(reg, sysarg, proc);
  else
    proc_outside(proc);

}

/** @brief handles getpeername syscall at the entrance */
void syscall_getpeername_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
  getpeername_arg_t arg = &(sysarg->getpeername);
  pid_t pid = proc->pid;

  arg->ret = (int) reg->ret;
  arg->sockfd = (int) reg->arg[0];
  /* arg->in = (sockaddr_in *) reg->arg[1]; */
  arg->sockaddr_dest = (void *) reg->arg[1];
  /* arg->len = (socklen_t *) reg->arg[2]; */
  arg->len_dest = (void *) reg->arg[2];
  ptrace_cpy(proc->pid, &(arg->len), arg->len_dest, sizeof(socklen_t), "getpeername");

  if (socket_registered(proc, arg->sockfd)) {
    if (socket_network(proc, arg->sockfd)) {
      struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
      struct sockaddr_in in;
      socklen_t size = 0;
      if (!comm_getpeername(is, &in, &size)) {
        if (size < arg->len)
          arg->len = size;
        arg->in = in;
        arg->ret = 0;
      } else
        arg->ret = -ENOTCONN;   /* ENOTCONN 107 End point not connected */

      ptrace_neutralize_syscall(pid);
      proc_outside(proc);
      ptrace_restore_syscall(pid, SYS_getpeername, arg->ret);
      if (arg->ret == 0) {
        ptrace_poke(pid, arg->len_dest, &(arg->len), sizeof(socklen_t));
        ptrace_poke(pid, arg->sockaddr_dest, &(arg->in), sizeof(struct sockaddr_in));
      }
      if (strace_option)
        print_getpeername_syscall(proc, sysarg);
    }
  }
}
