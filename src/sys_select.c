/* sys_select -- Handles select syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_select.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles select syscall at the entrance and the exit */
void syscall_select(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_select_pre(reg, sysarg, proc);
  else
    proc_outside(proc);

}

/** @brief handles select syscall at the entrance */
// TODO
void syscall_select_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
  THROW_UNIMPLEMENTED;

  get_args_select(proc, reg, sysarg);
  if (strace_option)
    print_select_syscall(proc, sysarg);

  XBT_WARN("Select: Timeout not handled\n");

  XBT_DEBUG("Entering process_select_call");
  select_arg_t arg = &(proc->sysarg.select);
  int i;

  fd_set fd_rd, fd_wr, fd_ex;

  fd_rd = arg->fd_read;
  fd_wr = arg->fd_write;
  fd_ex = arg->fd_except;

  int match = 0;

  for (i = 0; i < arg->maxfd; ++i) {
    struct infos_socket *is = get_infos_socket(proc, i);
    //if i is NULL that means that i is not a socket
    if (is == NULL) {
      FD_CLR(i, &(fd_rd));
      FD_CLR(i, &(fd_wr));
      continue;
    }

    int sock_status = socket_get_state(is);
    if (FD_ISSET(i, &(fd_rd))) {
      if ((sock_status & SOCKET_READ_OK) || (sock_status & SOCKET_CLOSED) || (sock_status & SOCKET_SHUT))
        ++match;
      else
        FD_CLR(i, &(fd_rd));
    }
    if (FD_ISSET(i, &(fd_wr))) {
      if ((sock_status & SOCKET_WR_NBLK) && !(sock_status & SOCKET_CLOSED) && !(sock_status & SOCKET_SHUT))
        ++match;
      else
        FD_CLR(i, &(fd_wr));
    }
    if (FD_ISSET(i, &(fd_ex))) {
      XBT_WARN("Select does not handle exception states for now");
    }
  }
  if (match > 0) {
    XBT_DEBUG("match for select");
    arg->fd_read = fd_rd;
    arg->fd_write = fd_wr;
    arg->fd_except = fd_ex;
    arg->ret = match;
    sys_build_select(proc, &(proc->sysarg), match);
    if (strace_option)
      print_select_syscall(proc, &(proc->sysarg));
  }
}
