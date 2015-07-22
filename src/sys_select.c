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
void syscall_select(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_select_pre(reg, proc);
  else
    proc_outside(proc);

}

/** @brief handles select syscall at the entrance */
// TODO
void syscall_select_pre(reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);
  THROW_UNIMPLEMENTED;
  int fd_state;
  fd_set fd_read, fd_write, fd_exec;
    
  ptrace_cpy(proc->pid, &fd_read, (void *) reg->arg[1], sizeof(fd_set), "select");
  ptrace_cpy(proc->pid, &fd_write, (void *) reg->arg[2], sizeof(fd_set), "select");
  ptrace_cpy(proc->pid, &fd_exec, (void *) reg->arg[3], sizeof(fd_set), "select");
  
 if ( (int) reg->arg[1] != 0) {
    fd_state = fd_state | SELECT_FDRD_SET;
  } else
   FD_ZERO(&fd_read);

  if ( (int) reg->arg[2] != 0) {
    fd_state = fd_state | SELECT_FDWR_SET;
  } else
    FD_ZERO(&fd_write);

  if ( (int) reg->arg[3] != 0) {
    fd_state = fd_state | SELECT_FDEX_SET;
  } else
    FD_ZERO(&fd_exec);

  if ( (int) reg->arg[4] != 0) {
    struct timeval t;
    reg->arg[4] = t.tv_sec + 0.000001 * t.tv_usec;
  } else
    reg->arg[4] = -1;

  if (strace_option)
    print_select_syscall(reg, proc, fd_state);

  XBT_WARN("Select: Timeout not handled\n");

  XBT_DEBUG("Entering process_select_call");
  int i;

  int match = 0;

  for (i = 0; i < (int) reg->arg[0]; ++i) {
    struct infos_socket *is = get_infos_socket(proc, i);
    //if i is NULL that means that i is not a socket
    if (is == NULL) {
      FD_CLR(i, &(fd_read));
      FD_CLR(i, &(fd_write));
      continue;
    }

    int sock_status = socket_get_state(is);
    if (FD_ISSET(i, &(fd_read))){
      if ((sock_status & SOCKET_READ_OK) || (sock_status & SOCKET_CLOSED) || (sock_status & SOCKET_SHUT))
        ++match;
      else
        FD_CLR(i, &(fd_read));
    }
    if (FD_ISSET(i, &(fd_write))) {
      if ((sock_status & SOCKET_WR_NBLK) && !(sock_status & SOCKET_CLOSED) && !(sock_status & SOCKET_SHUT))
        ++match;
      else
        FD_CLR(i, &(fd_read));
    }
    if (FD_ISSET(i, &(fd_exec))) {
      XBT_WARN("Select does not handle exception states for now");
    }
  }
  if (match > 0) {
    XBT_DEBUG("match for select");
   reg->ret = match;

  ptrace_restore_syscall(proc->pid, SYS_select, match);
  /* TODO: Old sys_build_select */
  /* reg_s r; */
  /* ptrace_get_register(pid, &r); */

  /* select_arg_t arg = &(sysarg->select); */

  /* if (arg->fd_state & SELECT_FDRD_SET) { */
  /*   ptrace_poke(pid, (void *) r.arg[1], &(arg->fd_read), sizeof(fd_set)); */
  /* } */
  /* if (arg->fd_state & SELECT_FDWR_SET) { */
  /*   ptrace_poke(pid, (void *) r.arg[2], &(arg->fd_write), sizeof(fd_set)); */
  /* } */
  /* if (arg->fd_state & SELECT_FDEX_SET) { */
  /*   ptrace_poke(pid, (void *) r.arg[3], &(arg->fd_except), sizeof(fd_set)); */
  /* } */

    if (strace_option)
      print_select_syscall(reg, proc, fd_state);
  }
}
